const fs=require('fs'), vm=require('vm');
const FILE=process.env.LP_FILE;
if(!FILE){console.error('need LP_FILE');process.exit(2)}
const src=fs.readFileSync(FILE,'utf8');
function mkEl(tag){return {tagName:tag,style:{},dataset:{},children:[],className:'',id:'',
  appendChild(c){this.children.push(c);return c},removeChild(c){},remove(){},
  setAttribute(){},getAttribute(){return null},addEventListener(){},removeEventListener(){},
  querySelector(){return null},querySelectorAll(){return []},insertBefore(c){return c},
  get firstChild(){return null},set innerHTML(v){this._h=v},get innerHTML(){return this._h||''},
  set textContent(v){this._t=v},get textContent(){return this._t||''},classList:{add(){},remove(){},toggle(){},contains(){return false}},
  focus(){},click(){},getBoundingClientRect(){return {top:0,left:0,width:0,height:0}}}}
const doc={readyState:'complete',documentElement:mkEl('html'),head:mkEl('head'),body:mkEl('body'),
  createElement:mkEl,createElementNS:(ns,t)=>mkEl(t),getElementById:()=>null,
  querySelector:()=>null,querySelectorAll:()=>[],addEventListener(){},removeEventListener(){},
  createTextNode:t=>({nodeValue:t}),cookie:''};
const store={}; 
const win={document:doc,navigator:{userAgent:'node',clipboard:{writeText:()=>Promise.resolve()}},
  localStorage:{getItem:k=>k in store?store[k]:null,setItem:(k,v)=>store[k]=String(v),removeItem:k=>delete store[k]},
  sessionStorage:{getItem:()=>null,setItem(){},removeItem(){}},
  location:{href:'http://127.0.0.1:12800/',origin:'http://127.0.0.1:12800',pathname:'/',search:'',hash:''},
  MutationObserver:class{observe(){}disconnect(){}},setInterval:()=>0,clearInterval(){},setTimeout:(f,t)=>0,clearTimeout(){},
  performance:{now:()=>Date.now()},alert(){},confirm:()=>true,prompt:()=>null,
  fetch:()=>Promise.reject(new Error('no-net')),FormData:class{},Blob:class{},
  URL:{createObjectURL:()=>'blob:x',revokeObjectURL(){}},URLSearchParams:class{},
  addEventListener(){},removeEventListener(){},console,
  TextEncoder:class{encode(s){return Buffer.from(s)}},TextDecoder:class{},
  requestIdleCallback:f=>f({timeRemaining:()=>10}),crypto:{randomUUID:()=>'x'},
  getComputedStyle:()=>({getPropertyValue:()=>''}),matchMedia:()=>({matches:false,addEventListener(){}})};
win.window=win; win.self=win; win.globalThis=win; win.top=win; win.parent=win;
const ctx=vm.createContext(win);
vm.runInContext(src,ctx,{filename:'awdpplus.js'});
const api=win.__lpAwdpPlusApi;
if(!api){console.error('no api; keys='+Object.keys(win).filter(k=>/lp|Awdp/i.test(k)));process.exit(3)}
module.exports=api;
