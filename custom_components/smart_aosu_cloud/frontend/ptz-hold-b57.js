/* Smart AOSU Cloud b57 — native authenticated MJPEG Lovelace PTZ card.
 * JS only; no credentials, persistent state, stored camera identifiers or
 * direct vendor connection. All actions use authenticated HA services.
 */
class SmartAosuPtzLiveB57 extends HTMLElement {
  constructor() {
    super();
    this.attachShadow({mode:'open'});
    this._config=null;
    this._hass=null;
    this._active=null;
    this._armed=false;
    this._ready=false;
    this._arming=false;
    this._timer=null;
    this._videoWanted=false;
    this._streamSrc=null;
    this._img=null;
    this._startingDirect=false;
    this._readyTimer=null;
    this._onBlur=()=>this._release('fenetre_inactive');
    this._onHide=()=>{if(document.hidden)this._release('onglet_inactif');};
  }
  setConfig(config) {
    if(!config || typeof config.camera_entity!=='string' || !config.camera_entity.startsWith('camera.'))
      throw new Error('camera_entity: camera.votre_c5l est requis');
    this._config=config;
    this._render();
  }
  set hass(hass) {
    this._hass=hass;
    // MJPEG camera access tokens rotate in HA; reconnect only on a change.
    if(this._videoWanted && this._img){
      const next=this._mjpegUrl();
      if(next && next!==this._streamSrc){
        this._streamSrc=next;
        this._videoMessage('Jeton du direct renouvelé ; reconnexion de l’affichage MJPEG…');
        this._img.src=next;
      }
    }
  }
  getCardSize(){return 6;}
  connectedCallback(){window.addEventListener('blur',this._onBlur);document.addEventListener('visibilitychange',this._onHide);}
  disconnectedCallback(){clearTimeout(this._readyTimer);this._ready=false;this._release('carte_fermee');this._closeMjpeg();window.removeEventListener('blur',this._onBlur);document.removeEventListener('visibilitychange',this._onHide);}
  _render(){
    if(!this.shadowRoot || !this._config)return;
    this.shadowRoot.innerHTML=`
      <style>
        ha-card{display:block;padding:12px;background:var(--card-background-color);color:var(--primary-text-color)}
        h3{margin:4px 0 10px;font-size:1rem} .preview{min-height:120px;background:#12161b;border-radius:9px;overflow:hidden}
        .preview img{display:block;width:100%;height:auto;aspect-ratio:16/9;object-fit:contain;background:#12161b}
        .video-info{font-size:12px;line-height:1.45;color:var(--primary-text-color,#fff);padding:10px;background:var(--secondary-background-color)}
        .toolbar{display:flex;gap:8px;margin:8px 0;flex-wrap:wrap}
        button{border:1px solid var(--divider-color);border-radius:10px;background:var(--secondary-background-color);
          color:var(--primary-text-color);font:inherit;cursor:pointer;min-height:42px}
        .toolbar button{padding:0 14px}
        .pad{display:grid;grid-template-columns:repeat(3,64px);grid-template-rows:repeat(3,52px);
          justify-content:center;gap:7px;margin:12px auto}
        .pad button{font-size:23px;touch-action:none;user-select:none;-webkit-user-select:none;
          -webkit-touch-callout:none}
        .pad button:active,.pad button.pressed{background:var(--primary-color);color:var(--text-primary-color,#fff)}
        .pad button:disabled{opacity:.35;cursor:not-allowed}
        .mid{grid-area:2/2;font-size:11px!important}
        .up{grid-area:1/2}.left{grid-area:2/1}.right{grid-area:2/3}.down{grid-area:3/2}
        label{display:flex;align-items:start;gap:8px;font-size:13px;margin:10px 0;cursor:pointer}
        input{margin:2px 0 0;accent-color:var(--primary-color)}
        .warning{font-size:12px;color:var(--warning-color,#dd8800);line-height:1.4}
        .status{font-size:12px;min-height:35px;border-top:1px solid var(--divider-color);padding-top:7px}
      </style>
      <ha-card>
        <h3>C5L — Direct et PTZ expérimental</h3>
        <div class="preview" id="preview"></div>
        <div class="video-info" id="video-info" role="status" aria-live="polite">Direct MJPEG inactif. Cliquer sur « Démarrer le direct ».</div>
        <div class="toolbar"><button id="play">▶ Démarrer le direct</button><button id="stoplive">■ Arrêter le direct</button><button id="refresh-display">Actualiser l’image</button><button id="direct-status">Diagnostic du direct</button><button id="prepare">Préparer PTZ</button><button id="check">Diagnostic des appuis</button></div>
        <label><input id="consent" type="checkbox"/> J'autorise un essai moteur limité à 0,75 s (STOP non confirmé physiquement).</label>
        <div class="pad" aria-label="Directions expérimentales">
          <button class="up" data-dir="up" aria-label="Haut">↑</button>
          <button class="left" data-dir="left" aria-label="Gauche">←</button>
          <button class="mid" id="emergency" aria-label="Relâcher et arrêter">STOP</button>
          <button class="right" data-dir="right" aria-label="Droite">→</button>
          <button class="down" data-dir="down" aria-label="Bas">↓</button>
        </div>
        <p class="warning">Test non validé sur le moteur. Relâcher envoie STOP ; sécurité serveur : maximum 0,75 s.
        Si la caméra continue à bouger, l'arrêter immédiatement dans l'application AOSU.</p>
        <div class="status" id="status" aria-live="polite">Direct requis ; commandes désactivées par défaut.</div>
      </ha-card>`;
    // The MJPEG viewer is independent of HA lazy-loaded picture cards.
    // Attach PTZ listeners first; video opens only on the explicit Play click.
    this._img=null;
    this._streamSrc=null;
    this._videoWanted=false;
    this._status=this.shadowRoot.getElementById('status');
    this._buttons=[...this.shadowRoot.querySelectorAll('[data-dir]')];
    const consent=this.shadowRoot.getElementById('consent');
    consent.addEventListener('change',()=>{this._armed=consent.checked;if(!this._armed){this._ready=false;clearTimeout(this._readyTimer);this._release('consentement_retire');}else{void this._arm();}this._sync();});
    this.shadowRoot.getElementById('play').addEventListener('click',()=>void this._playLive());
    this.shadowRoot.getElementById('stoplive').addEventListener('click',()=>void this._stopLive());
    this.shadowRoot.getElementById('refresh-display').addEventListener('click',()=>this._refreshDisplay());
    this.shadowRoot.getElementById('direct-status').addEventListener('click',()=>void this._videoStatusCheck());
    this.shadowRoot.getElementById('prepare').addEventListener('click',()=>void this._arm());
    this.shadowRoot.getElementById('check').addEventListener('click',()=>void this._statusCheck());
    this.shadowRoot.getElementById('emergency').addEventListener('click',()=>{
      if(this._active)this._release('stop_manuel');
      else this._message('Aucun appui actif : ce bouton n\'a pas envoyé de STOP. Si besoin, utiliser AOSU.');
    });
    for(const btn of this._buttons){
      btn.addEventListener('pointerdown',e=>{if(e.button!==0 || !e.isPrimary)return;
        e.preventDefault();try{btn.setPointerCapture(e.pointerId);}catch(_){}
        this._press(btn.dataset.dir,btn);
      });
      for(const event of ['pointerup','pointercancel','lostpointercapture','pointerleave']){
        btn.addEventListener(event,()=>this._release(event));
      }
      btn.addEventListener('contextmenu',e=>e.preventDefault());
      btn.addEventListener('keydown',e=>{if((e.key===' '||e.key==='Enter')&&!e.repeat){
        e.preventDefault();this._press(btn.dataset.dir,btn);}});
      btn.addEventListener('keyup',e=>{if(e.key===' '||e.key==='Enter'){e.preventDefault();this._release('touche_relachee');}});
    }
    this._sync();
    // HA C5L is native MJPEG, not CameraEntityFeature.STREAM (HLS/WebRTC).
    // An image is opened only after the user deliberately presses Play.
  }
  _videoMessage(message){
    const el=this.shadowRoot?.getElementById('video-info');
    if(el)el.textContent=message;
  }
  _mjpegUrl(){
    const id=this._config?.camera_entity;
    const token=this._hass?.states?.[id]?.attributes?.access_token;
    if(!id || typeof token!=='string' || !token)return null;
    return '/api/camera_proxy_stream/'+encodeURIComponent(id)+'?token='+encodeURIComponent(token);
  }
  _closeMjpeg(){
    this._videoWanted=false;
    this._streamSrc=null;
    if(this._img){
      this._img.onload=null;
      this._img.onerror=null;
      this._img.removeAttribute('src');
      this._img.remove();
      this._img=null;
    }
  }
  _openMjpeg(){
    const holder=this.shadowRoot?.getElementById('preview');
    if(!holder)return false;
    const entity=this._config?.camera_entity;
    if(!this._hass?.states?.[entity]){
      this._videoMessage('Entité caméra introuvable dans Home Assistant : vérifier camera_entity dans la carte.');
      return false;
    }
    const url=this._mjpegUrl();
    if(!url){
      this._videoMessage('Jeton de la caméra indisponible ; vérifier que l’entité C5L Direct est bien chargée.');
      return false;
    }
    // Use HA's authenticated MJPEG proxy; never embed vendor URLs or keys.
    this._closeMjpeg();
    this._videoWanted=true;
    const img=document.createElement('img');
    img.alt='C5L — flux MJPEG';
    img.loading='eager';
    img.addEventListener('load',()=>{
      if(this._img===img)this._videoMessage('Direct MJPEG affiché. Contrôles PTZ toujours expérimentaux.');
    });
    img.addEventListener('error',()=>{
      if(this._img===img)this._videoMessage('Le flux MJPEG n’affiche pas d’image. Cliquer sur « Diagnostic du direct », puis sur « Actualiser l’image » si nécessaire.');
    });
    holder.replaceChildren(img);
    this._img=img;
    this._streamSrc=url;
    this._videoMessage('Démarrage accepté ; attente des premières images MJPEG (la négociation P2P peut durer plusieurs secondes)…');
    img.src=url;
    return true;
  }
  async _playLive(){
    if(this._startingDirect)return;
    const entity=this._config?.camera_entity;
    if(!this._hass?.states?.[entity]){
      this._videoMessage('Entité caméra introuvable : '+String(entity||'non configurée')+'. Vérifier le YAML de la carte.');
      return;
    }
    if(!this._mjpegUrl()){
      this._videoMessage('Jeton MJPEG absent pour cette caméra. Vérifier les états Home Assistant.');
      return;
    }
    this._startingDirect=true;
    this._videoMessage('Demande de démarrage P2P vers Home Assistant…');
    try{
      const response=await this._service('demarrer_direct_c5l',{
        confirmation_envoi_mot_de_passe:true,confirmation_camera_c5l:true});
      if(response===null){
        this._videoMessage('Le service « Démarrer le direct » a échoué. Consulter les journaux Home Assistant.');
        return;
      }
      const payload=response?.response||response;
      const state=payload?.etat;
      if(!['demarrage_demande','direct_deja_en_cours','reprise_direct_existant'].includes(state)){
        const safe=(typeof state==='string' && /^[a-z0-9_]{1,90}$/.test(state))?state:'reponse_inattendue';
        this._videoMessage('Démarrage vidéo refusé : '+safe+'. Cliquer sur « Diagnostic du direct ».');
        return;
      }
      this._openMjpeg();
    }finally{this._startingDirect=false;}
  }
  async _stopLive(){
    this._release('arret_direct');
    const result=await this._service('arreter_direct_c5l',{});
    if(result===null){this._videoMessage('Arrêt du direct non confirmé. Vérifier les journaux Home Assistant.');return;}
    this._closeMjpeg();
    this._videoMessage('Arrêt du direct demandé ; affichage MJPEG fermé.');
  }
  _refreshDisplay(){
    if(!this._videoWanted){
      this._videoMessage('Le direct n’a pas été démarré dans cette carte. Utiliser « Démarrer le direct ».');
      return;
    }
    this._openMjpeg(); // Reopen the HA viewer, never restart the Tuya P2P session.
  }
  async _videoStatusCheck(){
    const response=await this._service('statut_direct_c5l',{});
    if(response===null){this._videoMessage('Diagnostic direct indisponible ; consulter les journaux HA.');return;}
    const result=response?.response||response;
    const state=typeof result?.etat==='string'?result.etat:'inconnu';
    const active=result?.direct_actif===true?'oui':'non';
    const count=result?.decodage?.images_jpeg_decodees;
    const images=Number.isSafeInteger(count)?count:'non indiqué';
    this._videoMessage('État direct : '+state+' | P2P actif : '+active+' | images JPEG décodées : '+images+'.');
  }
  _sync(){
    for(const b of this._buttons||[]){
      // Critical: disabling the *pressed* button can cause pointercancel
      // and trigger STOP before the directional command reaches HA.
      b.disabled=!this._armed || (!this._ready && this._active?.button!==b);
    }
  }
  async _arm(){
    if(!this._armed || this._arming || this._active || !this._hass)return;
    this._arming=true;this._ready=false;clearTimeout(this._readyTimer);this._sync();
    this._message('Ouverture de la connexion MQTT PTZ (aucun mouvement)...');
    const result=await this._service('ptz_live_c5l_b56',{action:'arm',confirmation_test_moteur:true});
    this._arming=false;
    if(!this._armed)return;
    const value=result?.etat||result?.response?.etat;
    this._ready=value==='session_prete';
    this._message(this._ready?'Connexion prête : maintenir une flèche pour tester.':
      'PTZ non prêt : '+String(value||'consulter les journaux HA'));
    // The server expires prepared connections after 20 s. Do not leave
    // enabled arrows showing a session that is no longer valid.
    if(this._ready)this._readyTimer=setTimeout(()=>{
      if(this._ready && !this._active){this._ready=false;this._sync();
        this._message('Connexion PTZ expirée : cliquer sur Préparer PTZ, puis appuyer dans les 20 secondes.');}
    },17000);
    this._sync();
  }
  _message(text){if(this._status)this._status.textContent=text;}
  async _service(name,data){
    if(!this._hass) {this._message('Home Assistant non disponible');return null;}
    try{return await this._hass.callService('smart_aosu_cloud',name,data,undefined,false,true);}
    catch(_){this._message('Action HA refusée ou indisponible. Vérifier le journal Home Assistant.');return null;}
  }
  async _statusCheck(){
    const raw=await this._service('ptz_live_c5l_b56',{action:'status'});
    const res=raw?.response||raw;
    if(!res){this._message('Aucun résultat du service PTZ. Vérifier les journaux HA.');return;}
    const n=res.compteurs||{};
    this._message('HA: '+String(res.etat||'inconnu')+
      ' | press reçus: '+(n.press_recus??'?')+' | directions envoyées (socket): '+(n.directions_envoyees_socket??'?')+
      ' | STOP envoyés (socket): '+(n.stops_envoyes_socket??'?')+
      ' | dernier appui: '+String(res.dernier_appui||'aucun'));
  }
  _newGesture(){
    if(globalThis.crypto && globalThis.crypto.getRandomValues){
      const bytes=new Uint8Array(16);globalThis.crypto.getRandomValues(bytes);
      return [...bytes].map(v=>v.toString(16).padStart(2,'0')).join('');
    }
    return String(Date.now())+String(Math.floor(Math.random()*1e12)).padStart(12,'0');
  }
  _press(direction,button){
    if(!this._armed || !this._ready || this._active || !this._hass)return;
    const id=this._newGesture();
    this._active={id,button};this._ready=false;clearTimeout(this._readyTimer);this._sync();button.classList.add('pressed');
    this._message('Publication directionnelle demandee (execution non confirmee)...');
    this._service('ptz_live_c5l_b56',{action:'press',direction,gesture_id:id,confirmation_test_moteur:true})
      .then(raw=>{const result=raw?.response||raw;
        if(this._active?.id===id && result?.etat && result.etat!=='demande_direction_en_cours'){
          this._message('Press refusé : '+result.etat);this._release('refus_serveur');}});
    this._timer=setTimeout(()=>this._release('limite_750ms'),750);
  }
  _release(_why){
    if(!this._active)return;
    const {id,button}=this._active;
    this._active=null;button.classList.remove('pressed');this._sync();
    clearTimeout(this._timer);this._timer=null;
    this._message('STOP demande ; aucune preuve de l\u2019arret physique.');
    void this._service('ptz_live_c5l_b56',{action:'release',gesture_id:id});
    setTimeout(async()=>{
      if(!this._armed)return;
      const result=await this._service('ptz_live_c5l_b56',{action:'status'});
      const state=result?.etat||result?.response?.etat||'';
      if(state.includes('ouvrir_appli_aosu'))this._message('ALERTE : STOP MQTT non confirme. Ouvrir AOSU immediatement.');
      else if(state==='stop_puback_broker_non_confirmation_camera')
        this._message('STOP recu par le broker, mais AUCUNE confirmation de la camera.');
    },2000);
    // Test-mode cooldown is enforced by HA too. Reconnect after it, not while
    // the command may still be stopping, and never if consent was removed.
    setTimeout(()=>{if(this._armed && !this._active)void this._arm();},4500);
  }
}
customElements.define('smart-aosu-ptz-live-b57',SmartAosuPtzLiveB57);
window.customCards=window.customCards||[];
window.customCards.push({type:'smart-aosu-ptz-live-b57',name:'Smart AOSU C5L — Direct + PTZ diagnostic b57',
  description:'Carte direct plus PTZ expérimental, diagnostics des appuis, sécurité 0,75 s.'});
