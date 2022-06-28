import './docs.scss';
import { SCFPaper } from '@scfhq/foundation-uax';

import React from 'react';

const DocsPage = () => (
  <SCFPaper className="p-4">
    <iframe
      src="../swagger-ui/index.html"
      width="100%"
      height="800"
      title="Swagger UI"
      seamless
      style={{ border: 'none' }}
      data-cy="swagger-frame"
    />
  </SCFPaper>
);

export default DocsPage;
