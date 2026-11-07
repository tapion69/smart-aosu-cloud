/* Smart AOSU Cloud b83 — native MJPEG + OEM HTTP PTZ (hold-to-move).
 * JS only; no credentials, persistent state, stored camera identifiers or
 * direct vendor connection. All actions use authenticated HA services.
 */
class SmartAosuPtzLiveB83 extends HTMLElement {
  constructor() {
    super();
    this.attachShadow({mode:'open'});
    this._config=null;
    this._hass=null;
    this._active=null;
    this._videoWanted=false;
    this._streamSrc=null;
    this._img=null;
    this._startingDirect=false;
    this._onBlur=()=>this._release('fenetre_inactive',true);
    this._onHide=()=>{if(document.hidden)this._release('onglet_inactif',true);};
  }
  setConfig(config) {
    if(!config || typeof config.camera_entity!=='string' || !config.camera_entity.startsWith('camera.'))
      throw new Error('camera_entity: camera.votre_c5l est requis');
    this._config=config;
    this._render();
  }
  set hass(hass) {
    this._hass=hass;
    this._sync();
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
  disconnectedCallback(){this._release('carte_fermee',true);this._closeMjpeg();window.removeEventListener('blur',this._onBlur);document.removeEventListener('visibilitychange',this._onHide);}
  _render(){
    if(!this.shadowRoot || !this._config)return;
    this.shadowRoot.innerHTML=`
      <style>
        ha-card{display:block;padding:12px;background:var(--card-background-color);color:var(--primary-text-color)}
        h3{margin:4px 0 10px;font-size:1rem} .preview{min-height:120px;background:#12161b;border-radius:9px;overflow:hidden}
        .preview:fullscreen{width:100vw;height:100vh;max-height:100vh;min-height:0;aspect-ratio:auto;border-radius:0;background:#000}.preview:fullscreen img{width:100%;height:100%;max-height:100vh;object-fit:contain}.preview img{display:block;width:100%;height:auto;aspect-ratio:16/9;object-fit:contain;background:#12161b}
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
        .status{display:none;font-size:12px;min-height:35px;border-top:1px solid var(--divider-color);padding-top:7px}
      </style>
      <ha-card>
        <h3>C5L — Direct et PTZ</h3>
        <div class="preview" id="preview"></div>
        <div class="video-info" id="video-info" role="status" aria-live="polite">Direct MJPEG inactif. Cliquer sur « Démarrer le direct ».</div>
        <div class="toolbar"><button id="play">▶ Démarrer le direct</button><button id="stoplive">■ Arrêter le direct</button><button id="fullscreen">⛶ Plein écran</button></div>
        <div class="pad" aria-label="Commandes PTZ">
          <button class="up" data-dir="up" aria-label="Haut">↑</button>
          <button class="left" data-dir="left" aria-label="Gauche">←</button>
          <button class="mid" id="emergency" aria-label="Relâcher et arrêter">STOP</button>
          <button class="right" data-dir="right" aria-label="Droite">→</button>
          <button class="down" data-dir="down" aria-label="Bas">↓</button>
        </div>
        <div class="status" id="status" aria-live="polite">Flèches disponibles. Le STOP reste accessible à tout moment.</div>
      </ha-card>`;
    // The MJPEG viewer is independent of HA lazy-loaded picture cards.
    // Attach PTZ listeners first; video opens only on the explicit Play click.
    this._img=null;
    this._streamSrc=null;
    this._videoWanted=false;
    this._status=this.shadowRoot.getElementById('status');
    this._buttons=[...this.shadowRoot.querySelectorAll('[data-dir]')];
    this.shadowRoot.getElementById('play').addEventListener('click',()=>void this._playLive());
    this.shadowRoot.getElementById('stoplive').addEventListener('click',()=>void this._stopLive());
    this.shadowRoot.getElementById('fullscreen').addEventListener('click',()=>{
      const preview=this.shadowRoot?.getElementById('preview');
      if(preview?.requestFullscreen){void preview.requestFullscreen().catch(()=>{});}
    });
    this.shadowRoot.getElementById('emergency').addEventListener('click',()=>this._stopNow());
    for(const btn of this._buttons){
      btn.addEventListener('pointerdown',e=>{if(e.button!==0 || !e.isPrimary)return;
        e.preventDefault();try{btn.setPointerCapture(e.pointerId);}catch(_){}
        this._press(btn.dataset.dir,btn);
      });
      for(const event of ['pointerup','pointercancel','lostpointercapture','pointerleave']){
        btn.addEventListener(event,()=>this._release(event,event!=='pointerup'));
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
      if(this._img===img)this._videoMessage('Direct MJPEG affiché. Les flèches PTZ fonctionnent indépendamment de la vidéo.');
    });
    img.addEventListener('error',()=>{
      if(this._img===img)this._videoMessage('Le flux MJPEG n’affiche pas d’image. Relancer le direct si nécessaire.');
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
        this._videoMessage('Démarrage vidéo refusé : '+safe+'. Consulter les journaux Home Assistant si nécessaire.');
        return;
      }
      this._openMjpeg();
    }finally{this._startingDirect=false;}
  }
  async _stopLive(){
    this._release('arret_direct',true);
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
    // Do not disable the active button; that could cause an unexpected
    // pointercancel and a premature STOP on some browsers.
    for(const b of this._buttons||[]){
      b.disabled=!this._hass || (this._active!==null && this._active.button!==b);
    }
  }
  _message(text){if(this._status)this._status.textContent=text;}
  async _service(name,data){
    if(!this._hass){this._message('Home Assistant indisponible');return null;}
    try{return await this._hass.callService('smart_aosu_cloud',name,data,undefined,false,true);}
    catch(_){this._message('Action HA refusée ou indisponible. Vérifier les journaux.');return null;}
  }
  async _statusCheck(){
    const raw=await this._service('ptz_maintien_c5l_b83',{action:'status'});
    const res=raw?.response||raw;
    if(!res){this._message('État PTZ indisponible');return;}
    const active=res.action_active?'mouvement en cours':'repos';
    const stop=res.stop_accepte_serveur===true?'STOP accepté serveur':
      res.stop_accepte_serveur===false?'STOP non confirmé':'STOP non sollicité';
    this._message('PTZ : '+active+' — '+String(res.etat||'inconnu')+' — '+stop);
  }
  _newGesture(){
    if(globalThis.crypto && globalThis.crypto.getRandomValues){
      const bytes=new Uint8Array(16);globalThis.crypto.getRandomValues(bytes);
      return [...bytes].map(v=>v.toString(16).padStart(2,'0')).join('');
    }
    return String(Date.now())+String(Math.floor(Math.random()*1e12)).padStart(12,'0');
  }
  _press(direction,button){
    const directions={up:'haut',down:'bas',left:'gauche',right:'droite'};
    if(!this._hass||this._active||!directions[direction])return;
    const id=this._newGesture();
    // Pending is used to serialize a fast touch release after the press service.
    const active={id,button,finished:false,accepted:false,pressPromise:null};
    this._active=active;
    button.classList.add('pressed');this._sync();
    this._message('Commande '+directions[direction]+' demandée…');
    active.pressPromise=this._service('ptz_maintien_c5l_b83',
      {action:'press',direction:directions[direction],gesture_id:id}).then(raw=>{
        const result=raw?.response||raw;
        active.accepted=result?.etat==='appui_recu';
        if(!active.accepted){
          if(this._active===active){this._active=null;button.classList.remove('pressed');this._sync();}
          this._message('PTZ : '+String(result?.etat||'commande non acceptée'));
        }
        return active.accepted;
      });
  }
  _release(reason,emergency=false){
    const active=this._active;
    if(!active||active.finished)return;
    active.finished=true;
    this._active=null;
    active.button.classList.remove('pressed');this._sync();
    this._message('Relâchement : STOP demandé…');
    // Wait for the press response so HA never sees release before press.
    void active.pressPromise.then(accepted=>{
      if(accepted){
        return this._service('ptz_maintien_c5l_b83',
          {action:emergency?'stop':'release',gesture_id:active.id});
      }
    });
  }
  _stopNow(){
    this._release('stop_manuel',true);
    // STOP must also work without an active gesture or with another browser.
    void this._service('ptz_maintien_c5l_b83',{action:'stop'});
    this._message('STOP d’urgence demandé — surveiller la caméra.');
  }
}
customElements.define('smart-aosu-ptz-live-b83',SmartAosuPtzLiveB83);
window.customCards=window.customCards||[];
window.customCards.push({type:'smart-aosu-ptz-live-b83',name:'Smart AOSU C5L — Direct + PTZ b83',
  description:'Vidéo MJPEG facultative, quatre directions appui maintenu, STOP au relâchement.'});
