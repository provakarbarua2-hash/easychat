importScripts('https://www.gstatic.com/firebasejs/10.12.2/firebase-app-compat.js');
importScripts('https://www.gstatic.com/firebasejs/10.12.2/firebase-messaging-compat.js');
firebase.initializeApp({
  apiKey: 'AIzaSyBc34XcK-oMXYNCJvgWGNeARd5E024rypY',
  authDomain: 'easychat-2856c.firebaseapp.com',
  databaseURL: 'https://easychat-2856c-default-rtdb.firebaseio.com',
  projectId: 'easychat-2856c',
  storageBucket: 'easychat-2856c.appspot.com',
  messagingSenderId: '697155725373',
  appId: '1:697155725373:web:a7da2906b04aa868bb6254'
});
const messaging = firebase.messaging();
messaging.onBackgroundMessage((payload) => {
  // Firebase Console-এর "Send test message" (notification-টাইপ) SDK নিজেই দেখায় — দ্বিতীয়বার দেখাব না
  if (payload && payload.notification) return;
  const d = (payload && payload.data) || {};
  const call = d.kind === 'call';
  return self.registration.showNotification(d.title || 'Easy Chat', {
    body: d.body || '',
    icon: '/icon-192.png',
    badge: '/badge-96.png',
    tag: (call ? 'call-' : 'msg-') + (d.chatId || ''),
    renotify: true,
    requireInteraction: call,
    vibrate: call ? [700, 300, 700, 300, 700, 300, 700, 300, 700] : [200, 100, 200],
    data: { chatId: d.chatId || '' }
  });
});
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (e) => e.waitUntil(self.clients.claim()));
self.addEventListener('notificationclick', (e) => {
  e.notification.close();
  e.waitUntil(clients.matchAll({ type: 'window', includeUncontrolled: true }).then((list) => {
    for (const c of list) if ('focus' in c) return c.focus();
    return clients.openWindow('/');
  }));
});
