import './footer.scss';

import React from 'react';
import { Box, Container, Grid, Typography } from '@mui/material';
import FacebookIcon from '@mui/icons-material/Facebook';
import InstagramIcon from '@mui/icons-material/Instagram';
import TwitterIcon from '@mui/icons-material/Twitter';
import LinkedInIcon from '@mui/icons-material/LinkedIn';
import YouTubeIcon from '@mui/icons-material/YouTube';

const Footer = () => (
  <Box className="footer-container" sx={{ py: 4 }}>
    <Container maxWidth="lg">
      <Grid container py={4} spacing={4} justifyContent="flex-start" alignItems="baseline">
        <Grid item xs={12} md={3} justifyContent="flex-start">
          <Typography align={'center'} color={'white'} alignItems={'flext-start'}>
            <img src="content/images/santander-consumer-finance-main-logo.png" alt="Santander Logo" />
          </Typography>
        </Grid>
        <Grid item xs={12} md={6} justifyContent={'center'}>
          <Typography variant={'bodyXSmall'} align={'center'} color={'#212529'} fontWeight={'bold'}>
            © Banco Santander S.A. Todos los derechos reservados. Sede corporativa: CGS Av. Cantabria s/n 28660 Boadilla del Monte, Madrid
            (España)
          </Typography>
        </Grid>
        <Grid item xs={12} md={3} justifyContent={'center'}>
          <Grid container spacing={2} justifyContent={'center'}>
            <Grid item>
              <TwitterIcon sx={{ color: '#212529' }} />
            </Grid>
            <Grid item>
              <LinkedInIcon sx={{ color: '#212529' }} />
            </Grid>
            <Grid item>
              <FacebookIcon sx={{ color: '#212529' }} />
            </Grid>
            <Grid item>
              <InstagramIcon sx={{ color: '#212529' }} />
            </Grid>
            <Grid item>
              <YouTubeIcon sx={{ color: '#212529' }} />
            </Grid>
          </Grid>
        </Grid>
      </Grid>
    </Container>
  </Box>
);

export default Footer;
