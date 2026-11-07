/* Smart AOSU Cloud b140 — C9 H1L MJPEG Lovelace card.
 * Only explicit button clicks can start/stop Tuya sessions. C5L/PTZ untouched.
 * No account credentials, tokens, stored identifiers, or vendor requests in JS.
 */
class SmartAosuC9LiveB140 extends HTMLElement {
  constructor(){
    super();
    this.attachShadow({mode:'open'});
    this._config=null;
    this._hass=null;
    this._img=null;
    this._viewWanted=false;
    this._busy=false;
    this._pollTimer=null;
    this._polling=false;
    this._cameraId=null;
  }
  setConfig(config){
    if(!config || typeof config!=='object')throw new Error('Configuration C9 invalide');
    if(config.camera_entity!==undefined && (typeof config.camera_entity!=='string' ||
        !config.camera_entity.startsWith('camera.')))
      throw new Error('camera_entity doit être de type camera.xxx');
    // Currently only C9 #2 has verified RTC/LAN startup. Never accept another
    // camera selection by a quiet override in frontend config.
    const stationIp=config.ip_station;
    if(typeof stationIp!=='string'||!/^(?:\d{1,3}\.){3}\d{1,3}$/.test(stationIp))
      throw new Error('Configurer ip_station avec l’adresse IPv4 de votre station H1L');
    this._config={camera_entity:config.camera_entity||null,ip_station:stationIp};
    if(!this.shadowRoot?.querySelector('ha-card'))this._render();
    this._updateEntityLabel();
  }
  set hass(hass){
    this._hass=hass;
    this._updateEntityLabel();
  }
  getCardSize(){return 4;}
  connectedCallback(){if(this._viewWanted)this._startMonitor();}
  disconnectedCallback(){
    this._stopMonitor();
    this._closeViewer();
    // Do not stop the backend silently. Only Stop button stops the session.
  }
  _render(){
    this.shadowRoot.innerHTML=`
      <style>
        ha-card{display:block;padding:12px;background:var(--card-background-color);color:var(--primary-text-color)}
        h3{margin:4px 0 10px;font-size:1rem}
        .preview{min-height:120px;aspect-ratio:16/9;background:#12161b;border-radius:9px;overflow:hidden;display:flex;align-items:center}
        .preview:fullscreen{width:100vw;height:100vh;max-height:100vh;min-height:0;aspect-ratio:auto;border-radius:0;justify-content:center;background:#000}.preview:fullscreen img{height:100%;width:100%;max-height:100vh;object-fit:contain}.preview img{display:block;width:100%;height:auto;object-fit:contain;background:#12161b}
        .video-info{font-size:12px;line-height:1.5;padding:10px;background:var(--secondary-background-color);white-space:pre-wrap}
        .toolbar{display:flex;gap:8px;margin:8px 0;flex-wrap:wrap}
        button{border:1px solid var(--divider-color);border-radius:10px;background:var(--secondary-background-color);
          color:var(--primary-text-color);font:inherit;cursor:pointer;padding:0 12px;min-height:42px}
        button:disabled{opacity:.5;cursor:wait}
        .private-meta{display:none}.note{font-size:12px;color:var(--secondary-text-color);line-height:1.5}
        .warning{color:var(--warning-color,#df9000)}
        .status{display:none;font-size:12px;line-height:1.5;border-top:1px solid var(--divider-color);padding-top:8px;white-space:pre-wrap}
      </style>
      <ha-card>
        <h3>C9 n°2 — Direct H1L (expérimental)</h3>
        <div class="preview" id="preview"></div>
        <div class="video-info" id="video-info" role="status" aria-live="polite">Direct C9 inactif. Cliquer sur « Démarrer le direct ».</div>
        <div class="toolbar">
          <button id="play">▶ Démarrer le direct</button>
          <button id="stop">■ Arrêter le direct</button>
          <button id="fullscreen">⛶ Plein écran</button>
        </div>
        <p class="note private-meta" id="entity-info"></p>
        <div class="status" id="status" role="status" aria-live="polite">Prêt. Aucune connexion lancée par l’affichage de cette carte.</div>
      </ha-card>`;
    this.shadowRoot.getElementById('play').addEventListener('click',()=>void this._play());
    this.shadowRoot.getElementById('fullscreen').addEventListener('click',()=>void this._fullscreen());
    this.shadowRoot.getElementById('stop').addEventListener('click',()=>void this._stop());
  }
  _fullscreen(){
    const preview=this.shadowRoot?.getElementById('preview');
    if(!this._img||!this._viewWanted){this._message('Démarrer la vidéo avant le plein écran.');return;}
    if(preview?.requestFullscreen){void preview.requestFullscreen().catch(()=>this._message('Plein écran non disponible sur cet appareil.'));return;}
    if(this._img?.webkitEnterFullscreen){this._img.webkitEnterFullscreen();return;}
    this._message('Plein écran non pris en charge par ce navigateur.');
  }
  _message(text){const el=this.shadowRoot?.getElementById('video-info');if(el)el.textContent=String(text);}
  _statusMessage(text){const el=this.shadowRoot?.getElementById('status');if(el)el.textContent=String(text);}
  _updateEntityLabel(){
    const el=this.shadowRoot?.getElementById('entity-info');
    if(!el)return;
    const id=this._findCameraId();
    el.textContent=id?'Caméra : '+id:'Entité caméra C9 H1L introuvable ou ambiguë. Indiquer camera_entity dans le YAML de la carte.';
  }
  _findCameraId(){
    const states=this._hass?.states;
    if(!states)return null;
    const specified=this._config?.camera_entity;
    if(specified)return states[specified]?specified:null;
    const matches=Object.entries(states).filter(([id,entity])=>{
      if(!id.startsWith('camera.'))return false;
      const name=String(entity?.attributes?.friendly_name||'')+' '+id.replaceAll('_',' ');
      return /c9.*h1l.*direct|h1l.*c9.*direct/i.test(name);
    }).map(([id])=>id);
    return matches.length===1?matches[0]:null;
  }
  _mjpegUrl(){
    const id=this._findCameraId();
    const token=id?this._hass?.states?.[id]?.attributes?.access_token:null;
    if(!id||typeof token!=='string'||!token)return null;
    return '/api/camera_proxy_stream/'+encodeURIComponent(id)+'?token='+encodeURIComponent(token);
  }
  _closeViewer(){
    this._viewWanted=false;
    this._stopMonitor();
    if(this._img){
      this._img.onload=null;this._img.onerror=null;
      this._img.removeAttribute('src');this._img.remove();this._img=null;
    }
    this.shadowRoot?.getElementById('preview')?.replaceChildren();
  }
  _openViewer(){
    const url=this._mjpegUrl();
    if(!url){
      this._message('Entité C9 ou jeton MJPEG indisponible. Contrôler la caméra C9 H1L dans Home Assistant.');
      return false;
    }
    const holder=this.shadowRoot?.getElementById('preview');if(!holder)return false;
    this._closeViewer();
    const img=document.createElement('img');
    img.alt='C9 n°2 H1L — direct MJPEG';img.loading='eager';
    img.addEventListener('load',()=>{if(this._img===img)this._message('Direct vidéo affiché.');});
    img.addEventListener('error',()=>{if(this._img===img)this._message('Vidéo indisponible. Arrêter puis redémarrer le direct si nécessaire.');});
    holder.replaceChildren(img);
    this._img=img;
    this._viewWanted=true;
    this._message('Session demandée ; attente du premier JPEG. La négociation RTC et FFmpeg peuvent prendre plusieurs secondes…');
    img.src=url;
    this._startMonitor();
    return true;
  }
  async _service(name,data){
    if(!this._hass){this._statusMessage('Home Assistant indisponible');return null;}
    try{return await this._hass.callService('smart_aosu_cloud',name,data,undefined,false,true);}
    catch(_){this._statusMessage('Service Smart AOSU indisponible ou refusé ; consulter les journaux Home Assistant.');return null;}
  }
  _payload(result){return result?.response||result;}
  async _play(){
    if(this._busy)return;
    if(!this._findCameraId()){
      this._message('Entité C9 H1L introuvable ou ambiguë. Vérifier camera_entity dans la configuration Lovelace.');return;
    }
    if(!this._mjpegUrl()){
      this._message('Jeton MJPEG absent sur l’entité C9 ; vérifier l’intégration et son état.');return;
    }
    this._busy=true;this._setBusy(true);
    this._message('Démarrage de la C9 n°2 demandé…');
    try{
      // Explicit Play click is the only action granting these permissions.
      // Never run automatically when the card is loaded, updated or refreshed.
      const data={
        nom_capture:'c9_camera_2_reference.pcap',
        ip_station:this._config.ip_station,camera_numero:2,
        confirmation_capture_personnelle:true,confirmation_camera_candidate:true,
        autoriser_reconstitution_oem:true,confirmation_envoi_mot_de_passe:true,
        autoriser_configuration_rtc:true,autoriser_offre_lan_active:true,
        autoriser_test_ice_actif:true,autoriser_test_kcp_actif:true,
        autoriser_auth_kcp_active:true,autoriser_essai_cle_station_b134:true,
        autoriser_commandes_video_c9_b137:true,autoriser_direct_c9_b139:true
      };
      const res=this._payload(await this._service('demarrer_direct_c9_b139',data));
      if(!res){this._message('Aucune réponse du service de démarrage C9. Consulter les journaux.');return;}
      const state=String(res?.etat||'reponse_inattendue');
      if(!['demarrage_direct_c9_lance','direct_c9_deja_en_cours'].includes(state)){
        const known={
          direct_c5l_en_cours:'Le direct C5L est actif : arrêter la C5L avant la C9.',
          autorisations_actives_completes_requises:'Autorisations du démarrage C9 non validées.',
          camera_c9_numero_2_requise:'Seule la caméra C9 n°2 est prise en charge.',
          ffmpeg_indisponible_ou_echec:'FFmpeg indisponible ou en échec dans Home Assistant.'
        };
        this._message(known[state]||'Démarrage non accepté : '+( /^[a-z0-9_]{1,80}$/.test(state)?state:'état inattendu'));
        return;
      }
      this._openViewer();
      this._statusMessage('Démarrage demandé. Le direct se terminera automatiquement après 100 secondes au plus.');
    }finally{this._busy=false;this._setBusy(false);}
  }
  async _stop(){
    if(this._busy)return;
    this._busy=true;this._setBusy(true);
    try{
      const res=this._payload(await this._service('arreter_direct_c9_b139',{}));
      this._closeViewer();
      if(!res){this._message('Arrêt demandé mais non confirmé. Vérifier les journaux Home Assistant.');return;}
      this._message(res?.etat==='direct_c9_arrete'?'Direct C9 arrêté.':'Arrêt C9 demandé. Vérifier le statut si la session reste active.');
      this._statusMessage('Aucune visualisation C9 en cours dans cette carte.');
    }finally{this._busy=false;this._setBusy(false);}
  }
  _refresh(){
    // Viewer refresh only: no new LAN, RTC, KCP or video-start command.
    if(!this._viewWanted){this._message('Démarrer le direct avant d’actualiser l’image.');return;}
    this._openViewer();
  }
  _setBusy(busy){
    for(const id of ['play','stop']){
      const button=this.shadowRoot?.getElementById(id);if(button)button.disabled=busy;
    }
  }
  async _statusCheck(){
    const res=this._payload(await this._service('statut_direct_c9_b139',{}));
    if(!res){this._statusMessage('Diagnostic C9 indisponible.');return null;}
    const state=String(res.etat||'inconnu');
    const frames=res?.decodage?.images_jpeg_decodees;
    const count=Number.isSafeInteger(frames)?frames:0;
    const active=res.direct_actif===true;
    const statusText='État : '+(/^[a-z0-9_]{1,90}$/.test(state)?state:'indéterminé')+
      ' | Session active : '+(active?'oui':'non')+
      ' | JPEG décodés : '+count+'.';
    this._statusMessage(statusText);
    if(count>0 && this._viewWanted){this._message('Décodage confirmé : '+count+' images JPEG. Affichage MJPEG ouvert.');}
    if(!active && this._viewWanted){
      this._closeViewer();
      this._message('Session C9 terminée. '+statusText+' Nouveau démarrage manuel requis (temporisation 15 min).');
    }
    return res;
  }
  _startMonitor(){
    if(this._pollTimer||!this.isConnected)return;
    // Poll state only, never auto-reconnect or auto-start the backend session.
    this._pollTimer=window.setInterval(()=>void this._poll(),5000);
  }
  _stopMonitor(){if(this._pollTimer){window.clearInterval(this._pollTimer);this._pollTimer=null;}}
  async _poll(){
    if(!this._viewWanted||this._polling)return;
    this._polling=true;
    try{await this._statusCheck();}finally{this._polling=false;}
  }
}
customElements.define('smart-aosu-c9-live-b140',SmartAosuC9LiveB140);
window.customCards=window.customCards||[];
window.customCards.push({type:'smart-aosu-c9-live-b140',
  name:'Smart AOSU — C9 n°2 direct H1L b140',
  description:'Direct C9 MJPEG expérimental avec Démarrer, Arrêter, Actualiser et Diagnostic, sans PTZ.'});
