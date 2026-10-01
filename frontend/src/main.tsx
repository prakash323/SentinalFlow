import React from 'react';
import ReactDOM from 'react-dom/client';

import '@fontsource-variable/inter';
import '@fontsource-variable/jetbrains-mono';

import App from './App';
import './styles/tokens.css';
import './styles/base.css';
import './styles/motion.css';
import './styles/components.css';
import './styles/layout.css';
import './styles/pages.css';

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
