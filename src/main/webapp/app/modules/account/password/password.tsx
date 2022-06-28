import React, { useState, useEffect, FormEvent } from 'react';
import { Translate, translate, ValidatedField, ValidatedForm } from 'react-jhipster';
import { Row, Col, Button } from 'reactstrap';
import { toast } from 'react-toastify';
import { SCFChangePasswordForm, SCFPaper } from '@scfhq/foundation-uax';
import Container from '@mui/material/Container';
import Box from '@mui/material/Box';
import Grid from '@mui/material/Grid';

import { useAppDispatch, useAppSelector } from 'app/config/store';
import { getSession } from 'app/shared/reducers/authentication';
import PasswordStrengthBar from 'app/shared/layout/password/password-strength-bar';
import { savePassword, reset } from './password.reducer';

interface DataType extends FormEvent<HTMLDivElement> {
  password: string;
  newPassword: string;
  newPasswordConfirm: string;
}

export const PasswordPage = () => {
  const [password, setPassword] = useState('');
  const dispatch = useAppDispatch();

  useEffect(() => {
    dispatch(reset());
    dispatch(getSession());
    return () => {
      dispatch(reset());
    };
  }, []);

  const handleValidSubmit = (currentPassword, newPassword) => {
    dispatch(savePassword({ currentPassword, newPassword }));
  };

  const handleSubmit = (data: DataType) => {
    setPassword(data.newPassword);
    handleValidSubmit(data.password, data.newPassword);
  };

  const account = useAppSelector(state => state.authentication.account);
  const successMessage = useAppSelector(state => state.password.successMessage);
  const errorMessage = useAppSelector(state => state.password.errorMessage);

  useEffect(() => {
    if (successMessage) {
      toast.success(translate(successMessage));
    } else if (errorMessage) {
      toast.success(translate(errorMessage));
    }
  }, [successMessage, errorMessage]);

  const newFunction = data => {
    alert(JSON.stringify(data));
  };

  return (
    <Box className="top-cover-image santander-default-bg" position={'relative'} sx={{ display: 'flex', alignItems: 'center', mb: 1 }}>
      <Container maxWidth="xl" sx={{ paddingTop: '35px' }}>
        <Grid container my={4} spacing={2} justifyContent="center">
          <Grid item>
            <SCFChangePasswordForm type="change" onSubmit={handleSubmit} />
          </Grid>
        </Grid>
      </Container>
    </Box>
  );
};

export default PasswordPage;
