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
