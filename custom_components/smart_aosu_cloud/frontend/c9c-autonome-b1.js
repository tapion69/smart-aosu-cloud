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
        <div class="actions"><button id="play">▶ Essayer la vidéo</button><button id="stop">■ Arrêter</button><button id="screen">⛶ Plein écran</button><button id="state">État</button><button id="identity">Vérifier identité</button><button id="detail">Fiche AOSU</button><button id="rtc">Examiner RTC</button><button id="v4rtc">Comparer RTC IPC</button><button id="observe">Observer MQTT</button></div>
        <p id="notice" role="status">Bêta : protocole vidéo C5L non validé sur C9C. PTZ volontairement désactivé. Aucun démarrage automatique.</p>
      </ha-card>`;
    this.shadowRoot.getElementById('play').addEventListener('click',()=>void this._play());
    this.shadowRoot.getElementById('stop').addEventListener('click',()=>void this._stop());
    this.shadowRoot.getElementById('state').addEventListener('click',()=>void this._state());
    this.shadowRoot.getElementById('identity').addEventListener('click',()=>void this._identity());
    this.shadowRoot.getElementById('detail').addEventListener('click',()=>void this._detail());
    this.shadowRoot.getElementById('rtc').addEventListener('click',()=>void this._rtc());
    this.shadowRoot.getElementById('v4rtc').addEventListener('click',()=>void this._v4rtc());
    this.shadowRoot.getElementById('observe').addEventListener('click',()=>void this._observe());
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
  async _identity() {
    if(this._busy)return;
    this._busy=true;
    const button=this.shadowRoot.getElementById('identity');
    if(button)button.disabled=true;
    this._message('Comparaison AOSU/Tuya : lecture du cache ou de l’inventaire Tuya, sans vidéo…');
    try {
      const response=await this._service('diagnostiquer_identite_c9c_autonome',{
        confirmation_lecture_tuya:true
      });
      const report=response?.response||response;
      if(!report || typeof report.etat!=='string')return;
      const match=report.correspondance||{};
      const aosu=report.identite_aosu||{};
      const device=report.unique_appareil_tuya||{};
      this._message('Diagnostic : '+report.etat+
        (report.cause ? ' ('+report.cause+')' : '')+
        ' ; liaison exacte : '+(match.identite_exacte_confirmee===true?'oui':'non')+
        ' ; SN concordants : '+String(match.serie_exacte_nombre??'?')+
        ' ; coopUUID concordants : '+String(match.coop_exact_nombre??'?')+
        ' ; coopUUID AOSU présent : '+(aosu.coop_uuid_present===true?'oui':'non')+
        ' ; catégorie Tuya absente : '+(device.categorie_absente===true?'oui':'non')+
        ' ; modèle Tuya présent : '+(device.modele_present===true?'oui':'non')+
        ' ; sélection RTC : '+String(match.selection_rtc||'non disponible')+
        ' ; SN=ID Tuya : '+String(match.serie_egale_id_tuya_nombre??'?')+
        ' ; branche PTZ AOSU : '+String((report.aosu_routage_declare||{}).branche_ptz||'indeterminee')+
        ' ; fournisseur P2P déclaré : '+String((report.aosu_routage_declare||{}).fournisseur_p2p||'INDETERMINE')+
        ' ; type P2P : '+String((report.aosu_routage_declare||{}).p2p_type??'absent')+
        ' ; référence Tuya : '+String((report.aosu_routage_declare||{}).reference_tuya||'indisponible')+
        '. Indices AOSU non confirmés par la vidéo. Aucune vidéo/commande PTZ envoyée par ce diagnostic.');
    } finally {
      this._busy=false;
      if(button)button.disabled=false;
    }
  }
  async _detail() {
    if (this._busy)return;
    this._busy=true;
    const btn=this.shadowRoot.getElementById('detail');
    if(btn)btn.disabled=true;
    this._message('Lecture unique de la fiche AOSU : aucune vidéo ni PTZ…');
    try {
      const response=await this._service('diagnostiquer_fiche_c9c_autonome',{
        confirmation_lecture_fiche:true
      });
      const data=response?.response||response;
      if(!data || typeof data.etat!=='string')return;
      if(data.etat!=='fiche_obtenue'){
        this._message('Fiche AOSU : '+data.etat+'. Aucune commande caméra envoyée.');
        return;
      }
      const yes=(v)=>v===true?'oui':'non';
      this._message('Fiche AOSU : obtenue ; références présentes : '+yes(data.references_connues_presentes)+
        ' ; SN concordant : '+yes(data.numero_serie_concordant)+
        ' ; SN contradictoire : '+yes(data.numero_serie_contradictoire)+
        ' ; lien référence/ID Tuya : '+yes(data.correspondance_reference_tuya)+
        ' ; fournisseur P2P déclaré : '+String(data.fournisseur_p2p_fiche||'INDETERMINE')+
        ' ; type P2P : '+String(data.type_p2p_fiche??'absent')+
        '. Sans vidéo ni PTZ.');
    } finally {
      this._busy=false;
      if(btn)btn.disabled=false;
    }
  }
  async _rtc() {
    if(this._busy)return;
    this._busy=true;
    const btn=this.shadowRoot.getElementById('rtc');
    if(btn)btn.disabled=true;
    this._message('Examen des paramètres RTC (lecture cloud, sans démarrer la caméra)…');
    try {
      const res=await this._service('diagnostiquer_rtc_c9c_autonome',{
        confirmation_lecture_rtc:true
      });
      const report=res?.response||res;
      if(!report||typeof report.etat!=='string')return;
      if(report.etat!=='configuration_rtc_obtenue'){
        this._message('RTC : '+report.etat+' ; sélection : '+String(report.selection||'?')+'. Aucune vidéo envoyée.');
        return;
      }
      const x=report.schema||{};
      const yn=v=>v===true?'oui':'non';
      this._message('RTC : accepté ; sélection : '+String(report.selection||'?')+
        ' ; moto_id : '+yn(x.moto_id_present)+
        ' ; pv : '+String(x.version_mqtt_pv_connue||'non_identifiee')+
        ' ; ICE : '+yn(x.serveurs_ice_presents)+
        ' ; TURN : '+yn(x.serveur_turn_dans_ices)+
        ' ; TCP : '+yn(x.relais_tcp_declare)+
        ' ; UDP : '+yn(x.relais_udp_declare)+
        ' ; clé locale : '+yn(x.cle_locale_presente)+
        '. Identité non prouvée. Aucun direct ni PTZ lancé.');
    } finally {
      this._busy=false;
      if(btn)btn.disabled=false;
    }
  }
  async _v4rtc() {
    if(this._busy)return;
    this._busy=true;
    const btn=this.shadowRoot.getElementById('v4rtc');
    if(btn)btn.disabled=true;
    this._message('Vérification RTC IPC-v4 (lecture cloud uniquement, sans vidéo)…');
    try {
      const r=await this._service('comparer_rtc_ipc_v4_c9c_autonome',{
        confirmation_lecture_rtc_v4:true
      });
      const d=r?.response||r;
      if(!d||typeof d.etat!=='string')return;
      if(d.etat!=='configuration_rtc_obtenue'){
        this._message('RTC IPC-v4 : '+d.etat+
          ' ; origine : '+String(d.origine_echec||'non_determinee')+
          '. Aucun message MQTT, vidéo ou PTZ envoyé.');
        return;
      }
      const x=d.schema||{};
      const yn=v=>v===true?'oui':'non';
      this._message('RTC IPC-v4 : accepté ; média prêt : '+
        yn(d.configuration_media_complete)+' ; session : '+
        yn(x.session_id_present)+' ; ICE : '+yn(x.serveurs_ice_presents)+
        ' ; TURN : '+yn(x.serveur_turn_dans_ices)+
        ' ; TCP : '+yn(x.relais_tcp_declare)+
        ' ; UDP : '+yn(x.relais_udp_declare)+
        ' ; moto_id : '+yn(x.moto_id_present)+
        ' ; pv : '+String(x.version_mqtt_pv_connue||'non_identifiee')+
        '. Aucun direct ni PTZ envoyé. Identité AOSU/Tuya non définitivement prouvée.');
    } finally {
      this._busy=false;
      if(btn)btn.disabled=false;
    }
  }
  async _observe() {
    if(this._busy)return;
    this._busy=true;
    const btn=this.shadowRoot.getElementById('observe');
    if(btn)btn.disabled=true;
    this._message('Ouvre maintenant le direct dans AOSU sur le téléphone. Écoute passive ~20 s après la préparation RTC…');
    try{
      const r=await this._service('observer_mqtt_c9c_autonome',{
        confirmation_ecoute_mqtt:true
      });
      const d=r?.response||r;
      if(!d||typeof d.etat!=='string')return;
      this._message('MQTT : '+d.etat+' ; appareil abonné : '+(d.abonnement_appareil===true?'oui':'non')+
        ' ; moto abonné : '+(d.abonnement_moto===true?'oui':'non')+
        ' ; messages appareil : '+String(d.messages_appareil??'?')+
        ' ; messages moto : '+String(d.messages_moto??'?')+
        ' ; trames 2.2 : '+String(d.trames_pv22??'?')+
        ' ; déchiffrées : '+String(d.decodages_ok??'?')+
        ' ; échecs décodage : '+String(d.decodages_echec??'?')+
        ' ; protocole 22/302/autres : '+String(d.protocoles_22??'?')+'/'+
              String(d.protocoles_302??'?')+'/'+String(d.protocoles_autres??'?')+
        ' ; types offre/réponse/candidat : '+String(d.types_offer??'?')+'/'+
              String(d.types_answer??'?')+'/'+String(d.types_candidate??'?')+
        ' ; source appareil confirmée : '+String(d.origine_appareil_confirmee??'?')+
        ' ; destinataire utilisateur confirmé : '+String(d.destinataire_utilisateur_confirme??'?')+
        ' ; SDP dans answer : '+String(d.answers_avec_sdp??'?')+
        ' ; AES/KCP : '+String(d.answers_aes_kcp??'?')+
        ' ; ICE candidats : '+String(d.candidates_avec_ice??'?')+
        ' ; path mqtt/autres : '+String(d.path_mqtt??'?')+'/'+String(d.path_autre??'?')+
        ' ; sessionid présent : '+String(d.sessionid_present??'?')+
        ' ; moto_id présent : '+String(d.moto_id_present??'?')+
        ' ; préparation : '+String(d.preparation||'?')+
        '. Aucune offre vidéo ou commande PTZ envoyée.');
    }finally{
      this._busy=false;
      if(btn)btn.disabled=false;
    }
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
    const sig=last.signalisation_b89||{};
    const count=(v)=>Number.isInteger(v)?v:'?';
    const noSdp=last.etat_mqtt==='offre_envoyee_sans_reponse_sdp';
    const motoInfo=' ; moto_id RTC : '+String(last.moto_id_source_rtc||'non_disponible')+
      ' ; moto_id dans offre : '+(last.moto_id_applique===true?'oui':'non');
    this._message(brief+(stage ? ' ; phase : '+stage : '')+
      (stage==='rtc_non_lance_c9c_non_identifiee'
        ? ' ; identification : '+selection+' ; caméras Tuya : '+cams+' / appareils Tuya : '+total+'. Ne pas relancer sans correction.'
        : ' ; sélection RTC : '+selection+' ; config RTC : '+String(last.configuration_rtc_acceptee===true?'acceptée':last.configuration_rtc_acceptee===false?'refusée':'inconnue')+
          (noSdp ? ' ; MQTT : sigQry='+count(sig.reponses_sigqry)+', autres='+count(sig.reponses_protocole_inattendu)+', 302 inconnu='+count(sig.messages_302_autres_types)+', 302 invalide='+count(sig.messages_302_format_invalide)+' ; SDP absente.'+motoInfo : '.'+motoInfo)));
  }
}
if(!customElements.get('smart-aosu-c9c-autonome-b1'))
  customElements.define('smart-aosu-c9c-autonome-b1',SmartAosuC9CAutonomeB1);
