/* Offline configuration-only test. No browser, Home Assistant, or network. */
'use strict';
const fs=require('node:fs');
const vm=require('node:vm');
const path=require('node:path');
const source=fs.readFileSync(path.join(__dirname,'../custom_components/smart_aosu_cloud/frontend/c9-live-b146.js'),'utf8');
let Card;
const context={
  HTMLElement:class {attachShadow(){this.shadowRoot={querySelector:()=>true,getElementById:()=>null};}},
  window:{customCards:[]},
  customElements:{define:(name,ctor)=>{if(name==='smart-aosu-c9-live-b146')Card=ctor;}},
};
vm.runInNewContext(source,context,{timeout:2000});
if(!Card)throw new Error('La carte C9 n\'est pas enregistrée');
function check(ip,expected){
  const card=new Card();let accepted=true;
  try{card.setConfig({camera_numero:1,ip_station:ip});}catch(_){accepted=false;}
  if(accepted!==expected)throw new Error('Validation IPv4 incohérente');
}
for(const ip of ['10.2.3.4','172.20.5.7','192.168.2.3'])check(ip,true);
for(const ip of ['8.8.8.8','127.0.0.1','172.32.0.1','300.2.3.4','192.168.0.999','10.0.0.01'])check(ip,false);
console.log('Carte C9 : validation hors réseau OK');
