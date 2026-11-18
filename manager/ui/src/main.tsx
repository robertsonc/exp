import { render } from 'preact';
import { App } from './app';
import { getStore } from './data/hooks';
import { applyTheme } from './lib/theme';
import { initRouter } from './router';
import '@shared/tokens.css';
import '@shared/base.css';
import './styles/app.css';

applyTheme();
initRouter();

// Immediate refetch when the tab becomes visible or the window regains focus.
document.addEventListener('visibilitychange', () => getStore().onResume());
window.addEventListener('focus', () => getStore().onResume());

const root = document.getElementById('app');
if (root) render(<App />, root);
