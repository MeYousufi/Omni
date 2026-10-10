const V="omni-v15";
self.addEventListener("install",e=>{self.skipWaiting();});
self.addEventListener("activate",e=>{
  e.waitUntil(
    // Nuclear: wipe EVERYTHING cached by any older version, then force every
    // open tab to reload fresh. Fixes clients stuck on stale code (2026-10-10).
    caches.keys().then(ks=>Promise.all(ks.map(k=>caches.delete(k))))
      .then(()=>self.clients.claim())
      .then(()=>self.clients.matchAll({type:"window",includeUncontrolled:true}))
      .then(clients=>{clients.forEach(c=>{try{c.navigate(c.url);}catch(e){}});})
  );
});
self.addEventListener("fetch",e=>{
  const u=new URL(e.request.url);
  // HTML pages: network first, bypass HTTP cache so updates always come through
  if(e.request.mode==="navigate"||u.pathname.endsWith(".html")||u.pathname==="/"||!u.pathname.includes(".")){
    e.respondWith(fetch(new Request(e.request,{cache:"reload"})).then(r=>{
      const c=r.clone();caches.open(V).then(cache=>cache.put(e.request,c));return r;
    }).catch(()=>caches.match(e.request)));
    return;
  }
  // everything else: cache first
  e.respondWith(caches.match(e.request).then(hit=>hit||fetch(e.request).then(r=>{
    const c=r.clone();caches.open(V).then(cache=>cache.put(e.request,c));return r;
  })));
});
