import './home.scss';

import React from 'react';
import { Link } from 'react-router-dom';
import { Translate } from 'react-jhipster';

import Container from '@mui/material/Container';
import Typography from '@mui/material/Typography';
import Box from '@mui/material/Box';
import Grid from '@mui/material/Grid';
import Button from '@mui/material/Button';
import CardActions from '@mui/material/CardActions';
import CardContent from '@mui/material/CardContent';
import Card from '@mui/material/Card';

import ArrowRightAltOutlinedIcon from '@mui/icons-material/ArrowRightAltOutlined';
import ExpandMoreIcon from '@mui/icons-material/ExpandMore';

import { useAppSelector } from 'app/config/store';

export const Home = () => {
  const account = useAppSelector(state => state.authentication.account);

  return (
    <>
      <Box className="top-cover-image santander-default-bg" position={'relative'} sx={{ display: 'flex', alignItems: 'center', mb: 0 }}>
        <Container maxWidth="lg">
          <Typography variant={'h6'} textTransform={'uppercase'} sx={{ mb: 2 }} align="center">
            Santander Consumer Finance
          </Typography>
          <Typography variant={'display3'} sx={{ pb: 4 }} align="center">
            App Generator Demo
          </Typography>
          <Box sx={{ p: 4 }}>
            {account && account.login && (
              <Typography variant={'h5'} textTransform={'none'} sx={{ mb: 2 }} align="center">
                <Translate contentKey="home.logged.message" interpolate={{ username: account.login }}>
                  You are logged in as user {account.login}.
                </Translate>
              </Typography>
            )}
          </Box>
        </Container>
      </Box>
    </>
  );
};

export default Home;
