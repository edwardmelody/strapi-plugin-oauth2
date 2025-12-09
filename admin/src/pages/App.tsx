import { Page } from '@strapi/strapi/admin';
import { Routes, Route } from 'react-router-dom';

import { HomePage } from './HomePage';
import { AccessTokensPage } from './AccessTokensPage';

const App = () => {
  return (
    <Routes>
      <Route index element={<HomePage />} />
      <Route path="access-tokens" element={<AccessTokensPage />} />
      <Route path="access-tokens/:clientDocumentId" element={<AccessTokensPage />} />

      {/* 404 ของ Strapi */}
      <Route path="*" element={<Page.Error />} />
    </Routes>
  );
};

export { App };
