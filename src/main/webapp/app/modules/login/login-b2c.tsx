import React, { useState } from 'react';

import { RouteComponentProps } from 'react-router-dom';
import { getUrlParameter } from 'react-jhipster';

import { useAppDispatch, useAppSelector } from 'app/config/store';
import { login } from './login-b2c-reducer';

export const B2CLogin = (props: RouteComponentProps<any>) => {
  const dispatch = useAppDispatch();
  const [id_token] = useState(getUrlParameter('id_token', props.location.search));

  dispatch(login(id_token));

  return <p></p>;
};

export default B2CLogin;
