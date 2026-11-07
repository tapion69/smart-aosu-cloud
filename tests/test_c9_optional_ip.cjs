const fs=require('fs'),vm=require('vm'),assert=require('assert');
const path=require('path');
const source=fs.readFileSync(path.join(__dirname,'../custom_components/smart_aosu_cloud/frontend/c9-live-b146.js'),'utf8');
class Element {attachShadow(){this.shadowRoot={querySelector(){return {}}};}}
const context={HTMLElement:Element,customElements:{define(){}},window:{customCards:[]},console};
vm.runInNewContext(source+'\n globalThis.TestClass=SmartAosuC9LiveB146;',context);
const card=new context.TestClass();
card._render=()=>{};card._updateEntityLabel=()=>{};card._updateHeading=()=>{};
card.setConfig({camera_numero:1,camera_entity:'camera.test'});
assert.strictEqual(card._config.ip_station,undefined);
card.setConfig({camera_numero:2,camera_entity:'camera.test',ip_station:'192.168.1.120'});
assert.strictEqual(card._config.ip_station,'192.168.1.120');
assert.throws(()=>card.setConfig({camera_numero:1,ip_station:'8.8.8.8'}),/ip_station/);
assert.throws(()=>card.setConfig({camera_numero:1,ip_station:'127.0.0.1'}),/ip_station/);
console.log('C9 optional station IP tests OK');
