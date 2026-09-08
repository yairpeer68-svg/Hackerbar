package com.yair.hackerbar

const val FORM_CAPTURE_SCRIPT = """
(() => {
  try {
    const f = document.activeElement && document.activeElement.form
      ? document.activeElement.form
      : document.querySelector('form');
    if (!f) return JSON.stringify({error:'No form found on this page'});
    const method = (f.method || 'GET').toUpperCase();
    const action = f.action || location.href;
    const type = f.enctype || 'application/x-www-form-urlencoded';
    const entries = [];
    new FormData(f).forEach((v, k) => {
      if (typeof v === 'string') entries.push([k, v]);
      else entries.push([k, '[file]']);
    });
    const body = new URLSearchParams(entries).toString().slice(0, 128000);
    return JSON.stringify({url:action, method:method, contentType:type, body:body});
  } catch (e) {
    return JSON.stringify({error:String(e)});
  }
})()
"""

const val API_CAPTURE_INSTALL_SCRIPT = """
(() => {
  if (window.__hbCaptureInstalled) return true;
  window.__hbCaptureInstalled = true;
  window.__hbRequests = [];
  const push = r => { try { window.__hbRequests.push(r); if (window.__hbRequests.length > 40) window.__hbRequests.shift(); } catch (_) {} };
  const oldFetch = window.fetch;
  window.fetch = function(input, init) {
    try {
      const req = new Request(input, init);
      const body = init && typeof init.body === 'string' ? init.body.slice(0,128000) : '';
      const headers = {}; req.headers.forEach((v,k)=>headers[k]=v);
      push({url:req.url,method:req.method||'GET',headers:headers,body:body,source:'fetch'});
    } catch (_) {}
    return oldFetch.apply(this, arguments);
  };
  const oldOpen = XMLHttpRequest.prototype.open, oldSend = XMLHttpRequest.prototype.send, oldSet = XMLHttpRequest.prototype.setRequestHeader;
  XMLHttpRequest.prototype.open = function(m,u){ this.__hb={method:String(m||'GET').toUpperCase(),url:new URL(u,location.href).href,headers:{}}; return oldOpen.apply(this,arguments); };
  XMLHttpRequest.prototype.setRequestHeader = function(k,v){ try { if(this.__hb) this.__hb.headers[String(k)]=String(v); } catch(_){} return oldSet.apply(this,arguments); };
  XMLHttpRequest.prototype.send = function(body){ try { if(this.__hb){ this.__hb.body=typeof body==='string'?body.slice(0,128000):''; this.__hb.source='xhr'; push(this.__hb); } } catch(_){} return oldSend.apply(this,arguments); };
  return true;
})()
"""

const val API_CAPTURE_LAST_SCRIPT = """
(() => JSON.stringify((window.__hbRequests && window.__hbRequests.length) ? window.__hbRequests[window.__hbRequests.length - 1] : {error:'No fetch/XHR request captured yet'}))()
"""
