import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import App from './App.jsx'

if (import.meta.env.PROD && 'serviceWorker' in navigator) {
  window.addEventListener('load', () => {
    navigator.serviceWorker.getRegistration('/').then((registration) => {
      if (registration?.active?.scriptURL === new URL('/sw.js', window.location.origin).href) {
        return registration.unregister()
      }
    }).catch(console.error)
    if ('caches' in window) {
      caches.keys().then((keys) => Promise.all(keys
        .filter((key) => key.startsWith('tracking-threats-offline-'))
        .map((key) => caches.delete(key)))).catch(console.error)
    }
  }, { once: true })
}

createRoot(document.getElementById('root')).render(
  <StrictMode>
    <App />
  </StrictMode>,
)
