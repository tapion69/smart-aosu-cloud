/* Smart AOSU Cloud b142 — C9 H1L MJPEG Lovelace card.
 * Only explicit button clicks can start/stop Tuya sessions. C5L/PTZ untouched.
 * No account credentials, tokens, stored identifiers, or vendor requests in JS.
 */
class SmartAosuC9LiveB142 extends HTMLElement {
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
    this._ptzReady=false;
    this._ptzMonitor=null;
    this._ptzChecking=false;
    this._gesture=null;
    this._onBlur=()=>this._releasePtz(true);
    this._onVisibility=()=>{if(document.hidden)this._releasePtz(true);};
  }
  setConfig(config){
    if(!config || typeof config!=='object')throw new Error('Configuration C9 invalide');
    if(config.camera_entity!==undefined && (typeof config.camera_entity!=='string' ||
        !config.camera_entity.startsWith('camera.')))
      throw new Error('camera_entity doit être de type camera.xxx');
    // Currently only C9 #2 has verified RTC/LAN startup. Never accept another
    // camera selection by a quiet override in frontend config.
    const number=config.camera_numero===undefined?2:config.camera_numero;
    if(!Number.isInteger(number)||![1,2].includes(number))
      throw new Error('camera_numero doit valoir 1 ou 2');
    const title=config.titre??config.nom;
    if(title!==undefined && (typeof title!=='string'||title.trim().length>100))
      throw new Error('titre doit être un texte de 100 caractères maximum');
    const stationIp=config.ip_station;
    if(typeof stationIp!=='string'||!/^(?:\d{1,3}\.){3}\d{1,3}$/.test(stationIp))
      throw new Error('Configurer ip_station avec l’adresse IPv4 de votre station H1L');
    this._config={camera_entity:config.camera_entity||null,camera_numero:number,titre:title?.trim()||null,ip_station:stationIp};
    if(!this.shadowRoot?.querySelector('ha-card'))this._render();
    this._updateEntityLabel();
    this._updateHeading();
  }
  set hass(hass){
    this._hass=hass;
    if(this._ptzMonitor)void this._autoPtzCheck();
    this._updateEntityLabel();
    this._updateHeading();
  }
  getCardSize(){return 4;}
  _number(){return this._config?.camera_numero||2;}
  connectedCallback(){
    this._startPtzMonitor();
    window.addEventListener('blur',this._onBlur);
    document.addEventListener('visibilitychange',this._onVisibility);
    if(this._viewWanted)this._startMonitor();
  }
  disconnectedCallback(){
    this._stopPtzMonitor();
    this._stopMonitor();
    this._releasePtz(true);
    this._closeViewer();
    window.removeEventListener('blur',this._onBlur);
    document.removeEventListener('visibilitychange',this._onVisibility);
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
        .pad{display:grid;grid-template-columns:repeat(3,64px);grid-template-rows:repeat(3,52px);justify-content:center;gap:7px;margin:12px auto}
        .pad button{font-size:23px;touch-action:none;user-select:none}
        .pad button:disabled{opacity:.35;cursor:not-allowed}
        .pad .up{grid-area:1/2}.pad .left{grid-area:2/1}.pad .right{grid-area:2/3}.pad .down{grid-area:3/2}.pad .middle{grid-area:2/2;font-size:11px}
        .private-meta{display:none}.note{font-size:12px;color:var(--secondary-text-color);line-height:1.5}
        .warning{color:var(--warning-color,#df9000)}
        .status{display:none;font-size:12px;line-height:1.5;border-top:1px solid var(--divider-color);padding-top:8px;white-space:pre-wrap}
      </style>
      <ha-card>
        <h3 id="camera-title">C9 n°${this._number()} — Direct H1L</h3>
        <div class="preview" id="preview"></div>
        <div class="video-info" id="video-info" role="status" aria-live="polite">Direct C9 inactif. Cliquer sur « Démarrer le direct ».</div>
        <div class="toolbar">
          <button id="play">▶ Démarrer le direct</button>
          <button id="stop">■ Arrêter le direct</button>
          <button id="fullscreen">⛶ Plein écran</button>
        </div>
        <div class="pad" aria-label="Commandes PTZ">
          <button class="up" data-dir="haut" disabled aria-label="Haut">↑</button>
          <button class="left" data-dir="gauche" disabled aria-label="Gauche">←</button>
          <button class="middle" id="ptzstop" aria-label="STOP">STOP</button>
          <button class="right" data-dir="droite" disabled aria-label="Droite">→</button>
          <button class="down" data-dir="bas" disabled aria-label="Bas">↓</button>
        </div>
        <p class="note private-meta" id="entity-info"></p>
        <div class="status" id="status" role="status" aria-live="polite">Prêt. Aucune connexion lancée par l’affichage de cette carte.</div>
      </ha-card>`;
    this.shadowRoot.getElementById('play').addEventListener('click',()=>void this._play());
    this.shadowRoot.getElementById('fullscreen').addEventListener('click',()=>void this._fullscreen());
    this.shadowRoot.getElementById('stop').addEventListener('click',()=>void this._stop());
    this.shadowRoot.getElementById('ptzstop').addEventListener('click',()=>void this._stopPtz());
    for(const btn of this.shadowRoot.querySelectorAll('[data-dir]')){
      btn.addEventListener('pointerdown',e=>{
        if(e.button!==0||!e.isPrimary)return;
        e.preventDefault();try{btn.setPointerCapture(e.pointerId);}catch(_){}
        this._pressPtz(btn.dataset.dir);
      });
      for(const ev of ['pointerup','pointercancel','lostpointercapture','pointerleave'])
        btn.addEventListener(ev,()=>this._releasePtz(false));
      btn.addEventListener('contextmenu',e=>e.preventDefault());
      btn.addEventListener('keydown',e=>{
        if(!e.repeat&&(e.key==='Enter'||e.key===' ')){
          e.preventDefault();this._pressPtz(btn.dataset.dir);}});
      btn.addEventListener('keyup',e=>{
        if(e.key==='Enter'||e.key===' '){e.preventDefault();this._releasePtz(false);}});
    }
  }
  _fullscreen(){
    const preview=this.shadowRoot?.getElementById('preview');
    if(!this._img||!this._viewWanted){this._message('Démarrer la vidéo avant le plein écran.');return;}
    if(preview?.requestFullscreen){void preview.requestFullscreen().catch(()=>this._message('Plein écran non disponible sur cet appareil.'));return;}
    if(this._img?.webkitEnterFullscreen){this._img.webkitEnterFullscreen();return;}
    this._message('Plein écran non pris en charge par ce navigateur.');
  }
  _updateHeading(){
    const heading=this.shadowRoot?.getElementById('camera-title');
    if(!heading)return;
    const custom=this._config?.titre;
    const entity=this._hass?.states?.[this._findCameraId()];
    const aosu=entity?.attributes?.nom_aosu;
    const friendly=entity?.attributes?.friendly_name;
    const recognized=typeof aosu==='string'&&aosu.trim()?aosu.trim():
      (typeof friendly==='string'&&!/^C9 H1L Direct/i.test(friendly)?friendly.trim():'');
    heading.textContent=custom||recognized||('C9 n°'+this._number()+' — Direct H1L');
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
    if(specified){
      const ent=states[specified];
      if(!ent)return null;
      const registered=ent.attributes?.camera_numero;
      if(registered!==undefined&&Number(registered)!==this._number())return null;
      return specified;
    }
    const matches=Object.entries(states).filter(([id,entity])=>{
      if(!id.startsWith('camera.'))return false;
      // Prefer the controller's stable attributes: users may rename both the
      // friendly name and the entity_id in Home Assistant.
      if(entity?.attributes?.camera_numero!==undefined){
        return Number(entity.attributes.camera_numero)===this._number() &&
          entity.attributes.sortie_mjpeg==='camera_proxy_stream';
      }
      const name=String(entity?.attributes?.friendly_name||'')+' '+id.replaceAll('_',' ');
      if(!/c9.*h1l.*direct|h1l.*c9.*direct/i.test(name))return false;
      // Compatibility fallback for previous B139 C9 #2 entity only.
      return this._number()===2&&/b139/i.test(name);
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
    img.alt='C9 n°'+this._number()+' H1L — direct MJPEG';img.loading='eager';
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
    this._message('Démarrage de la C9 n°'+this._number()+' demandé…');
    try{
      // Explicit Play click is the only action granting these permissions.
      // Never run automatically when the card is loaded, updated or refreshed.
      const data={
        nom_capture:this._number()===1?'c9_camera_1_reference.pcap':'c9_camera_2_reference.pcap',
        ip_station:this._config.ip_station,camera_numero:this._number(),
        confirmation_capture_personnelle:true,confirmation_camera_candidate:true,
        autoriser_reconstitution_oem:true,confirmation_envoi_mot_de_passe:true,
        autoriser_configuration_rtc:true,autoriser_offre_lan_active:true,
        autoriser_test_ice_actif:true,autoriser_test_kcp_actif:true,
        autoriser_auth_kcp_active:true,autoriser_essai_cle_station_b134:true,
        autoriser_commandes_video_c9_b137:true,autoriser_direct_c9_b139:true
      };
      const res=this._payload(await this._service('demarrer_direct_c9_b141',data));
      if(!res){this._message('Aucune réponse du service de démarrage C9. Consulter les journaux.');return;}
      const state=String(res?.etat||'reponse_inattendue');
      if(!['demarrage_direct_c9_lance','direct_c9_deja_en_cours'].includes(state)){
        const known={
          direct_c5l_en_cours:'Le direct C5L est actif : arrêter la C5L avant la C9.',
          autorisations_actives_completes_requises:'Autorisations du démarrage C9 non validées.',
          camera_c9_capture_incoherente:'Capture ne correspondant pas à la C9 sélectionnée.',
          ffmpeg_indisponible_ou_echec:'FFmpeg indisponible ou en échec dans Home Assistant.',
          capture_absente:'Capture personnelle de cette C9 absente de /config/smart_aosu_traces/.',
          identite_camera_capture_non_concordante:'La référence C9 de la capture ne correspond pas à l’inventaire OEM actuel.',
          auth_capture_invalide:'Capture C9 non exploitable ou authentification introuvable.',
          inventaire_camera_invalide:'Les deux C9 ne sont pas identifiées sans ambiguïté dans l’inventaire.'
        };
        this._message(known[state]||'Démarrage non accepté : '+( /^[a-z0-9_]{1,80}$/.test(state)?state:'état inattendu'));
        return;
      }
      this._openViewer();
      this._statusMessage('Direct persistant demandé. Arrêter manuellement pour fermer la session.');
    }finally{this._busy=false;this._setBusy(false);}
  }
  async _stop(){
    if(this._busy)return;
    this._busy=true;this._setBusy(true);
    try{
      const res=this._payload(await this._service('arreter_direct_c9_b141',{camera_numero:this._number()}));
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
    const res=this._payload(await this._service('statut_direct_c9_b141',{camera_numero:this._number()}));
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
      this._message('Session C9 terminée. '+statusText+' ');
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
  _startPtzMonitor(){
    if(this._ptzMonitor)return;
    this._ptzMonitor=window.setInterval(()=>void this._autoPtzCheck(),5000);
    if(this._hass)void this._autoPtzCheck();
  }
  _stopPtzMonitor(){
    if(this._ptzMonitor){window.clearInterval(this._ptzMonitor);this._ptzMonitor=null;}
    this._ptzReady=false;
    this._updatePtzButtons();
  }
  async _autoPtzCheck(){
    if(!this._hass||this._ptzChecking||!this.isConnected)return;
    this._ptzChecking=true;
    try{await this._ptzStatusCheck(true);}finally{this._ptzChecking=false;}
  }
  _updatePtzButtons(){
    for(const b of this.shadowRoot?.querySelectorAll('[data-dir]')||[])b.disabled=!this._ptzReady;
  }
  async _ptzStatusCheck(silent=false){
    const r=this._payload(await this._service('statut_ptz_c9_b141',
        {camera_numero:this._number()}));
    this._ptzReady=r?.commandes_ptz_autorisees===true;
    this._updatePtzButtons();
    if(!silent)this._statusMessage(this._ptzReady?
      "PTZ C9 : codes mouvement/STOP trouvés dans l'OEM. Test expérimental, STOP physique non garanti.":
      'PTZ C9 non validé : codes OEM mouvement/STOP absents ou caméra non identifiée. Aucun mouvement permis.');
    return r;
  }
  _pressPtz(direction){
    if(!this._ptzReady||this._gesture)return;
    const id=Date.now().toString(36)+'_'+Math.random().toString(36).slice(2,12);
    const entry={id,pending:null,released:false};this._gesture=entry;
    entry.pending=this._service('appui_ptz_c9_b141',
      {camera_numero:this._number(),direction,geste_id:id});
    void entry.pending.then(raw=>{
      const r=this._payload(raw);
      if(this._gesture===entry&&r?.etat!=='appui_recu'){
        this._statusMessage('PTZ non démarré : '+String(r?.etat||'inconnu'));
        this._gesture=null;
      }
      if(entry.released)void this._sendReleasePtz(entry);
    }).catch(()=>{if(this._gesture===entry)this._gesture=null;});
  }
  _releasePtz(emergency){
    const g=this._gesture;if(!g)return;
    g.released=true;
    // Delayed release only after appui was processed; never loose a fast click.
    if(g.pending)void g.pending.then(()=>this._sendReleasePtz(g)).catch(()=>this._stopPtz());
    if(emergency)void this._stopPtz();
  }
  async _sendReleasePtz(g){
    if(g.releasing)return;
    g.releasing=true;
    await this._service('relache_ptz_c9_b141',
      {camera_numero:this._number(),geste_id:g.id});
    if(this._gesture===g)this._gesture=null;
  }
  async _stopPtz(){
    if(this._gesture)this._gesture.released=true;
    const r=this._payload(await this._service('stop_ptz_c9_b141',
      {camera_numero:this._number()}));
    this._statusMessage('STOP PTZ demandé. Arrêt physique non mesuré.'+
      (r?.etat?' État : '+String(r.etat):''));
  }

}
customElements.define('smart-aosu-c9-live-b142',SmartAosuC9LiveB142);
window.customCards=window.customCards||[];
window.customCards.push({type:'smart-aosu-c9-live-b142',
  name:'Smart AOSU — C9 H1L 1 ou 2 + PTZ b142',
  description:'Direct C9 1 ou 2, sans limite fixe, et PTZ conditionnel.'});
