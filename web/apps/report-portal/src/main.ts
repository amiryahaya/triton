import { createApp } from 'vue';
import { createPinia } from 'pinia';
import '@triton/ui/tokens.css';
import '@triton/ui/fonts.css';
import App from './App.vue';
import { router } from './router';

createApp(App).use(createPinia()).use(router).mount('#app');
