import { createApp } from 'vue'
import App from './App.vue'
import { router } from './router'
import { registerApiNavigator } from './api/client'
import './style.css'

registerApiNavigator((path) => {
  if (router.currentRoute.value.path !== path) {
    void router.push(path)
  }
})

createApp(App).use(router).mount('#app')
