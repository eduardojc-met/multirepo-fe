import React, { useEffect } from 'react';
import { Redirect, RouteComponentProps } from 'react-router-dom';

import { useAppDispatch, useAppSelector } from 'app/config/store';

import { login } from 'app/shared/reducers/authentication';

import Container from '@mui/material/Container';
import Box from '@mui/material/Box';
import Grid from '@mui/material/Grid';

import { SCFLogin } from '@scfhq/foundation-uax';

export const Login = (props: RouteComponentProps<any>) => {
  const dispatch = useAppDispatch();
  const isAuthenticated = useAppSelector(state => state.authentication.isAuthenticated);
  const loginError = useAppSelector(state => state.authentication.loginError);

  const { location } = props;
  const { from } = (location.state as any) || { from: { pathname: '/', search: location.search } };

  if (isAuthenticated) {
    return <Redirect to={from} />;
  }

  const handleLogin = (username, password, rememberMe = false) => {
    return dispatch(login(username, password, rememberMe));
  };

  return (
    <Box className="top-cover-image santander-default-bg" position={'relative'} sx={{ display: 'flex', alignItems: 'center', mb: 4 }}>
      <Container maxWidth="xl">
        <Grid container py={4} spacing={2} justifyContent="flex-end">
          <Grid item>
            <SCFLogin onSubmit={handleLogin}  />
          </Grid>
        </Grid>
      </Container>
    </Box>
  );
};

export default Login;
