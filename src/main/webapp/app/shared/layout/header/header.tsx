import './header.scss';

import React, { useState, useEffect } from 'react';
import { Translate, Storage } from 'react-jhipster';
import { Home, Brand } from './header-components';
import { AdminMenu, EntitiesMenu, AccountMenu, LocaleMenu } from '../menus';
import { useAppDispatch } from 'app/config/store';
import { setLocale } from 'app/shared/reducers/locale';

import { SCFAppBar } from '@scfhq/foundation-uax';
import { Grid, IconButton, Toolbar, useMediaQuery } from '@mui/material';
import { Box } from '@mui/system';
import AppsIcon from '@mui/icons-material/Apps';

export interface IHeaderProps {
  isAuthenticated: boolean;
  isAdmin: boolean;
  ribbonEnv: string;
  isInProduction: boolean;
  isOpenAPIEnabled: boolean;
  currentLocale: string;
}

const Header = (props: IHeaderProps) => {
  const [menuOpen, setMenuOpen] = useState(false);
  const [appbarMenu, setAppbarMenu] = useState(true);
  const appBarResponsive = useMediaQuery('(min-width:900px)');

  const dispatch = useAppDispatch();

  const handleLocaleChange = event => {
    const langKey = event.target.value;
    Storage.session.set('locale', langKey);
    dispatch(setLocale(langKey));
  };

  const renderDevRibbon = () =>
    props.isInProduction === false ? (
      <div className="ribbon dev">
        <a href="">
          <Translate contentKey={`global.ribbon.${props.ribbonEnv}`} />
        </a>
      </div>
    ) : null;

  const toggleMenu = () => setMenuOpen(!menuOpen);
  const handleAppbarMenu = () => {
    setAppbarMenu(!appbarMenu);
  };
  useEffect(() => {
    if (appBarResponsive) {
      setAppbarMenu(true);
    }
  }, [appBarResponsive]);

  /* jhipster-needle-add-element-to-menu - JHipster will add new menu items here */
  return (
    <div id="app-header">
      {renderDevRibbon()}
      <SCFAppBar sx={{ position: 'absolute', backgroundColor: 'white' }} className="loading-bar">
        <Toolbar disableGutters className="jh-navbar" id="header-tabs">
          <Brand />
          <Grid container spacing={2} p={6} direction="row" maxWidth="xl" alignContent="flex-end" justifyContent="flex-end">
            <Box className="Appbar-menuContainer">
              <IconButton onClick={handleAppbarMenu} sx={{ zIndex: 1000, right: '-130px' }}>
                <AppsIcon sx={{ display: { xs: 'block', md: 'none' } }} className="Appbar-iconmenu" />
              </IconButton>
              {appbarMenu && (
                <Box className="Appbar-menu">
                  {props.isAuthenticated && <EntitiesMenu />}
                  {props.isAuthenticated && props.isAdmin && (
                    <AdminMenu showOpenAPI={props.isOpenAPIEnabled} showDatabase={!props.isInProduction} />
                  )}
                  <LocaleMenu currentLocale={props.currentLocale} onClick={handleLocaleChange} />
                  <AccountMenu isAuthenticated={props.isAuthenticated} />
                </Box>
              )}
            </Box>
          </Grid>
        </Toolbar>
      </SCFAppBar>
    </div>
  );
};

export default Header;
