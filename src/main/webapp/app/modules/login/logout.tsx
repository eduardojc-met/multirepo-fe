import React, { useLayoutEffect } from 'react';

import { useAppDispatch, useAppSelector } from 'app/config/store';
import { logout } from 'app/shared/reducers/authentication';

import { Box } from '@mui/material';
import { Container } from 'reactstrap';
import { SCFPaper } from '@scfhq/foundation-uax';

export const Logout = () => {
  const logoutUrl = useAppSelector(state => state.authentication.logoutUrl);
  const dispatch = useAppDispatch();

  useLayoutEffect(() => {
    dispatch(logout());
    if (logoutUrl) {
      window.location.href = logoutUrl;
    }
  });

  return (
    <Box className="top-cover-image santander-default-bg" position={'relative'} sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
      <Container maxWidth="xl">
        <SCFPaper className="p-4">
          <h4>Logged out successfully!</h4>
        </SCFPaper>
      </Container>
    </Box>
  );
};

export default Logout;
