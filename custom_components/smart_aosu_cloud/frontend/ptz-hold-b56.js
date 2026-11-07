/* Smart AOSU Cloud b56 — experimental Lovelace PTZ card.
 * JS only; no credentials, persistent state, stored camera identifiers or
 * direct vendor connection. All actions use authenticated HA services.
 */
class SmartAosuPtzLiveB56 extends HTMLElement {
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
    if(this._picture) this._picture.hass=hass;
  }
  getCardSize(){return 6;}
  connectedCallback(){window.addEventListener('blur',this._onBlur);document.addEventListener('visibilitychange',this._onHide);}
  disconnectedCallback(){clearTimeout(this._readyTimer);this._ready=false;this._release('carte_fermee');window.removeEventListener('blur',this._onBlur);document.removeEventListener('visibilitychange',this._onHide);}
  _render(){
    if(!this.shadowRoot || !this._config)return;
    this.shadowRoot.innerHTML=`
      <style>
        ha-card{display:block;padding:12px;background:var(--card-background-color);color:var(--primary-text-color)}
        h3{margin:4px 0 10px;font-size:1rem} .preview{min-height:120px}
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
        <div class="toolbar"><button id="play">▶ Démarrer le direct</button><button id="stoplive">■ Arrêter le direct</button><button id="prepare">Préparer PTZ</button><button id="check">Diagnostic des appuis</button></div>
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
    // IMPORTANT: HA lazy-loads hui-picture-entity-card.  Do not call
    // setConfig() on a potentially undefined element.  Wire buttons first;
    // build the video separately with the supported card helpers.
    this._picture=null;
    this._status=this.shadowRoot.getElementById('status');
    this._buttons=[...this.shadowRoot.querySelectorAll('[data-dir]')];
    const consent=this.shadowRoot.getElementById('consent');
    consent.addEventListener('change',()=>{this._armed=consent.checked;if(!this._armed){this._ready=false;clearTimeout(this._readyTimer);this._release('consentement_retire');}else{void this._arm();}this._sync();});
    this.shadowRoot.getElementById('play').addEventListener('click',()=>this._service('demarrer_direct_c5l',
      {confirmation_envoi_mot_de_passe:true,confirmation_camera_c5l:true}).then(()=>this._message('Demarrage du direct demande.')));
    this.shadowRoot.getElementById('stoplive').addEventListener('click',()=>{
      this._release('arret_direct');this._service('arreter_direct_c5l',{}).then(()=>this._message('Arret du direct demande.'));
    });
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
    // Video rendering is intentionally non-blocking: missing/lazy native
    // components must NEVER prevent pointerdown/keyup listeners.
    void this._loadPicture();
  }
  async _loadPicture(){
    const container=this.shadowRoot?.getElementById('preview');
    if(!container || !this._config)return;
    container.textContent='Chargement du direct...';
    try{
      if(typeof window.loadCardHelpers!=='function')throw Error('HA card helpers indisponibles');
      const helpers=await window.loadCardHelpers();
      if(!this._config || !this.shadowRoot?.getElementById('preview'))return;
      const card=helpers.createCardElement({type:'picture-entity',entity:this._config.camera_entity,
        camera_image:this._config.camera_entity,camera_view:'live',show_name:false,show_state:false});
      this._picture=card;
      if(this._hass)card.hass=this._hass;
      container.replaceChildren(card);
    }catch(_err){
      if(container)container.textContent='Aperçu vidéo indisponible dans cette carte. Le direct HA existant reste inchangé.';
    }
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
customElements.define('smart-aosu-ptz-live-b56',SmartAosuPtzLiveB56);
window.customCards=window.customCards||[];
window.customCards.push({type:'smart-aosu-ptz-live-b56',name:'Smart AOSU C5L — Direct + PTZ diagnostic b56',
  description:'Carte direct plus PTZ expérimental, diagnostics des appuis, sécurité 0,75 s.'});
