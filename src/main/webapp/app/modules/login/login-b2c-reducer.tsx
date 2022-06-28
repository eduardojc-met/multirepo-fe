import axios, { AxiosResponse } from 'axios';
import { createAsyncThunk, createSlice } from '@reduxjs/toolkit';
import { AppThunk } from 'app/config/store';
import { Storage } from 'react-jhipster';
import { serializeAxiosError } from 'app/shared/reducers/reducer.utils';

const AUTH_TOKEN_KEY = 'jhi-authenticationToken';

const initialState = {
  activationSuccess: false,
  activationFailure: false,
};

export type AuthenticationState = Readonly<typeof initialState>;

// Actions

export const authenticate = createAsyncThunk(
  'oauth2/authorization/oidc',
  async (id_token: string) => axios.get(`auth/oidc?id_token=${id_token}`),
  {
    serializeError: serializeAxiosError,
  }
);

export const login: (id_token: string) => AppThunk = id_token => async dispatch => {
  const result = await dispatch(authenticate(id_token));
  const response = result.payload as AxiosResponse;
  if (response.status === 200) {
    const bearerToken = response?.headers?.authorization;
    if (bearerToken && bearerToken.slice(0, 7) === 'Bearer ') {
      const jwt = bearerToken.slice(7, bearerToken.length);
      Storage.session.set(AUTH_TOKEN_KEY, jwt);
      window.location.href = '/';
    }
  }
};

export const AuthenticationSlice = createSlice({
  name: 'authentication',
  initialState: initialState as AuthenticationState,
  reducers: {},
  extraReducers(builder) {},
});

// Reducer
export default AuthenticationSlice.reducer;
