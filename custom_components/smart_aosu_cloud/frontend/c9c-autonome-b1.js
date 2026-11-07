/* Smart AOSU Cloud - standalone C9C VIDEO-ONLY pilot.
 * This view never sends any PTZ command and never auto-starts/retries P2P.
 */
class SmartAosuC9CAutonomeB1 extends HTMLElement {
  constructor() {
    super();
    this.attachShadow({mode: 'open'});
    this._config = null;
    this._hass = null;
    this._img = null;
    this._busy = false;
  }
  setConfig(config) {
    if (!config || typeof config.camera_entity !== 'string' ||
        !config.camera_entity.startsWith('camera.')) {
      throw new Error('camera_entity: camera.votre_c9c_autonome requis');
    }
    if (this._config?.camera_entity === config.camera_entity && this.shadowRoot.querySelector('ha-card')) return;
    this._config = config;
    this._render();
  }
  set hass(value) { this._hass = value; }
  getCardSize() { return 4; }
  disconnectedCallback() { this._close(); }
  _render() {
    this.shadowRoot.innerHTML = `
      <style>
        ha-card{padding:12px;background:var(--card-background-color);color:var(--primary-text-color)}
        h3{margin:2px 0 10px;font-size:1rem}
        .view{width:100%;aspect-ratio:16/9;background:#11161b;display:flex;align-items:center;justify-content:center;overflow:hidden;border-radius:8px}
        .view img{width:100%;height:100%;object-fit:contain}
        .view:fullscreen{width:100vw;height:100vh;aspect-ratio:auto}
        .actions{display:flex;flex-wrap:wrap;gap:8px;margin:12px 0}
        button{min-height:42px;padding:4px 12px;background:var(--secondary-background-color);color:var(--primary-text-color);border:1px solid var(--divider-color);border-radius:8px;cursor:pointer}
        button:disabled{opacity:.5}
        p{font-size:12px;line-height:1.4;margin:8px 0;color:var(--secondary-text-color)}
      </style>
      <ha-card>
        <h3>C9C autonome — essai vidéo P2P</h3>
        <div id="view" class="view"></div>
        <div class="actions"><button id="play">▶ Essayer la vidéo</button><button id="stop">■ Arrêter</button><button id="screen">⛶ Plein écran</button><button id="state">État</button></div>
        <p id="notice" role="status">Bêta : protocole vidéo C5L non validé sur C9C. PTZ volontairement désactivé. Aucun démarrage automatique.</p>
      </ha-card>`;
    this.shadowRoot.getElementById('play').addEventListener('click',()=>void this._play());
    this.shadowRoot.getElementById('stop').addEventListener('click',()=>void this._stop());
    this.shadowRoot.getElementById('state').addEventListener('click',()=>void this._state());
    this.shadowRoot.getElementById('screen').addEventListener('click',()=>{
      const element=this.shadowRoot.getElementById('view');
      if(element?.requestFullscreen) void element.requestFullscreen().catch(()=>{});
    });
  }
  _message(value) { const node=this.shadowRoot.getElementById('notice');if(node)node.textContent=value; }
  _tokenUrl() {
    const state=this._hass?.states?.[this._config?.camera_entity];
    const token=state?.attributes?.access_token;
    if(!state || typeof token!=='string' || !token)return null;
    return '/api/camera_proxy_stream/'+encodeURIComponent(this._config.camera_entity)+'?token='+encodeURIComponent(token);
  }
  _close() {
    if(this._img){this._img.removeAttribute('src');this._img.remove();this._img=null;}
  }
  async _service(name,data={}) {
    if(!this._hass)return null;
    try {return await this._hass.callService('smart_aosu_cloud',name,data,undefined,false,true);}
    catch(_) {this._message('Service Home Assistant indisponible. Vérifier les journaux expurgés.');return null;}
  }
  async _play() {
    if(this._busy)return;
    const url=this._tokenUrl();
    if(!url){this._message('Entité vidéo C9C ou jeton caméra absent. Vérifier la configuration de cette carte.');return;}
    this._busy=true;
    this.shadowRoot.getElementById('play').disabled=true;
    try {
      this._message('Essai manuel de négociation vidéo P2P…');
      const response=await this._service('demarrer_video_c9c_autonome_beta',{
        confirmation_camera_c9c_autonome:true,
        confirmation_essai_video:true,
        confirmation_envoi_mot_de_passe:true
      });
      const result=response?.response||response;
      if(!['demarrage_demande','direct_deja_en_cours','reprise_direct_existant'].includes(result?.etat)){
        this._message('Démarrage non accepté : '+(typeof result?.etat==='string'?result.etat:'erreur')+'. Pas de PTZ envoyé.');
        return;
      }
      this._close();
      const img=document.createElement('img');
      img.alt='C9C — vidéo expérimentale';
      img.addEventListener('error',()=>this._message('Aucune image MJPEG affichable : consulter État.'));
      this.shadowRoot.getElementById('view').appendChild(img);
      this._img=img;
      img.src=url;
      this._message('Session lancée. Attendre les premières images, puis cliquer sur État pour le diagnostic.');
    } finally {
      this._busy=false;
      this.shadowRoot.getElementById('play').disabled=false;
    }
  }
  async _stop() {
    this._close();
    const response=await this._service('arreter_direct_c5l');
    this._message(response===null?'Arrêt non confirmé, vérifier les journaux.':'Arrêt du direct demandé.');
  }
  async _state() {
    const response=await this._service('statut_direct_c5l');
    const state=response?.response||response;
    if(!state){this._message('Diagnostic non disponible.');return;}
    const images=state?.decodage?.images_jpeg_decodees;
    const last=state?.dernier_resultat||{};
    const stage=typeof last.etat_negociation==='string' ? last.etat_negociation : '';
    const selection=typeof last.methode_selection_rtc==='string' ? last.methode_selection_rtc : '';
    const cams=Number.isInteger(last.cameras_tuya_categorie_video) ? last.cameras_tuya_categorie_video : '?';
    const total=Number.isInteger(last.nombre_appareils_tuya) ? last.nombre_appareils_tuya : '?';
    const brief='État : '+String(state.etat||'inconnu')+' ; JPEG : '+(Number.isInteger(images)?images:'?')+' ; P2P : '+(state.direct_actif===true?'oui':'non');
    this._message(brief+(stage ? ' ; phase : '+stage : '')+
      (stage==='rtc_non_lance_c9c_non_identifiee'
        ? ' ; identification : '+selection+' ; caméras Tuya : '+cams+' / appareils Tuya : '+total+'. Ne pas relancer sans correction.'
        : ' ; sélection RTC : '+selection+' ; config RTC : '+String(last.configuration_rtc_acceptee===true?'acceptée':last.configuration_rtc_acceptee===false?'refusée':'inconnue')+'.'));
  }
}
if(!customElements.get('smart-aosu-c9c-autonome-b1'))
  customElements.define('smart-aosu-c9c-autonome-b1',SmartAosuC9CAutonomeB1);
