// omni-v16: SELF-UNREGISTERING. Stale service workers were trapping old app
// code on some devices (2026-10-10). This version deletes all caches,
// unregisters itself, and reloads every open tab fresh. After this runs
// once, no service worker controls the site — every load is a fresh
// network request, so updates can never get stuck again.
self.addEventListener("install",e=>{self.skipWaiting();});
self.addEventListener("activate",e=>{
  e.waitUntil(
    caches.keys().then(ks=>Promise.all(ks.map(k=>caches.delete(k))))
      .then(()=>self.registration.unregister())
      .then(()=>self.clients.matchAll({type:"window",includeUncontrolled:true}))
      .then(clients=>{clients.forEach(c=>{try{c.navigate(c.url);}catch(e){}});})
  );
});
// No fetch handler: once unregistered, the browser handles all requests natively.
