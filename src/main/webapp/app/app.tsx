import 'react-toastify/dist/ReactToastify.css';
import './app.scss';

import '@scfhq/foundation-uax/dist/css/tier1.css';

import { setLocale } from 'app/shared/reducers/locale';

import 'app/config/dayjs.ts';

import React, { useEffect } from 'react';
import { BrowserRouter as Router, Link as RouterLink, LinkProps as RouterLinkProps, MemoryRouter } from 'react-router-dom';

import { ToastContainer, toast } from 'react-toastify';

import { useAppDispatch, useAppSelector } from 'app/config/store';
import { getSession } from 'app/shared/reducers/authentication';
import { getProfile } from 'app/shared/reducers/application-profile';
import Header from 'app/shared/layout/header/header';
import Footer from 'app/shared/layout/footer/footer';
import { hasAnyAuthority } from 'app/shared/auth/private-route';
import ErrorBoundary from 'app/shared/error/error-boundary';
import { AUTHORITIES } from 'app/config/constants';
import AppRoutes from 'app/routes';

import { ThemeProvider } from '@mui/material';
import { Tier1 } from '@scfhq/foundation-uax';

const baseHref = document.querySelector('base').getAttribute('href').replace(/\/$/, '');

// Update default typography styles with Flame variants
declare module '@mui/material/styles' {
  interface TypographyVariants {
    display1: React.CSSProperties;
    display2: React.CSSProperties;
    display3: React.CSSProperties;
    bodyLarge: React.CSSProperties;
    bodyMedium: React.CSSProperties;
    bodySmall: React.CSSProperties;
    bodyXSmall: React.CSSProperties;
  }

  // allow configuration using `createTheme`
  interface TypographyVariantsOptions {
    display1?: React.CSSProperties;
    display2?: React.CSSProperties;
    display3?: React.CSSProperties;
    bodyLarge?: React.CSSProperties;
    bodyMedium?: React.CSSProperties;
    bodySmall?: React.CSSProperties;
    bodyXSmall?: React.CSSProperties;
  }
}

// Update the Typography's variant prop options
declare module '@mui/material/Typography' {
  interface TypographyPropsVariantOverrides {
    display1: true;
    display2: true;
    display3: true;
    bodyLarge: true;
    bodyMedium: true;
    bodySmall: true;
    bodyXSmall: true;
  }
}

export const App = () => {
  const dispatch = useAppDispatch();

  useEffect(() => {
    dispatch(getSession());
    dispatch(getProfile());
  }, []);

  const currentLocale = useAppSelector(state => state.locale.currentLocale);
  const isAuthenticated = useAppSelector(state => state.authentication.isAuthenticated);
  const isAdmin = useAppSelector(state => hasAnyAuthority(state.authentication.account.authorities, [AUTHORITIES.ADMIN]));
  const ribbonEnv = useAppSelector(state => state.applicationProfile.ribbonEnv);
  const isInProduction = useAppSelector(state => state.applicationProfile.inProduction);
  const isOpenAPIEnabled = useAppSelector(state => state.applicationProfile.isOpenAPIEnabled);

  return (
    <ThemeProvider theme={Tier1}>
      <Router basename={baseHref}>
        <div className="app-container">
          <ToastContainer position={toast.POSITION.TOP_LEFT} className="toastify-container" toastClassName="toastify-toast" />
          <ErrorBoundary>
            <Header
              isAuthenticated={isAuthenticated}
              isAdmin={isAdmin}
              currentLocale={currentLocale}
              ribbonEnv={ribbonEnv}
              isInProduction={isInProduction}
              isOpenAPIEnabled={isOpenAPIEnabled}
            />
          </ErrorBoundary>
          <div id="app-view-container" className="view-container">
            <ErrorBoundary>
              <AppRoutes />
            </ErrorBoundary>
          </div>
          <Footer />
        </div>
      </Router>
    </ThemeProvider>
  );
};

export default App;
