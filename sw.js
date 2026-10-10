const V="omni-v13";
self.addEventListener("install",e=>{self.skipWaiting();});
self.addEventListener("activate",e=>{
  e.waitUntil(caches.keys().then(ks=>Promise.all(ks.filter(k=>k!==V).map(k=>caches.delete(k)))).then(()=>self.clients.claim()));
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
