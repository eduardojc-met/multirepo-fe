import React, { useState, useEffect } from 'react';
import { Link, RouteComponentProps } from 'react-router-dom';
import { Translate, getSortState } from 'react-jhipster';
import { FontAwesomeIcon } from '@fortawesome/react-fontawesome';
import { ITEMS_PER_PAGE, SORT } from 'app/shared/util/pagination.constants';
import { overridePaginationStateWithQueryParams } from 'app/shared/util/entity-utils';
import { getUsersAsAdmin, updateUser } from './user-management.reducer';

import { useAppDispatch, useAppSelector } from 'app/config/store';

import { SCFDataGrid, SCFPaper } from '@scfhq/foundation-uax';

import { GridColDef } from '@mui/x-data-grid';

import Box from '@mui/material/Box';
import Container from '@mui/material/Container';
import { IUser } from 'app/shared/model/user.model';
import Stack from '@mui/material/Stack';
import Chip from '@mui/material/Chip';
import Button from '@mui/material/Button';

import IconButton from '@mui/material/IconButton';
import InfoIcon from '@mui/icons-material/Info';
import EditIcon from '@mui/icons-material/Edit';
import DeleteIcon from '@mui/icons-material/Delete';
import DownloadIcon from '@mui/icons-material/Download';

export const UserManagement = (props: RouteComponentProps<any>) => {
  const dispatch = useAppDispatch();

  const [pagination, setPagination] = useState(
    overridePaginationStateWithQueryParams(getSortState(props.location, ITEMS_PER_PAGE, 'id'), props.location.search)
  );

  const getUsersFromProps = () => {
    dispatch(
      getUsersAsAdmin({
        page: pagination.activePage - 1,
        size: pagination.itemsPerPage,
        sort: `${pagination.sort},${pagination.order}`,
      })
    );
    const endURL = `?page=${pagination.activePage}&sort=${pagination.sort},${pagination.order}`;
    if (props.location.search !== endURL) {
      props.history.push(`${props.location.pathname}${endURL}`);
    }
  };

  useEffect(() => {
    getUsersFromProps();
  }, [pagination.activePage, pagination.order, pagination.sort]);

  useEffect(() => {
    const params = new URLSearchParams(props.location.search);
    const page = params.get('page');
    const sortParam = params.get(SORT);
    if (page && sortParam) {
      const sortSplit = sortParam.split(',');
      setPagination({
        ...pagination,
        activePage: +page,
        sort: sortSplit[0],
        order: sortSplit[1],
      });
    }
  }, [props.location.search]);

  const handleSyncList = () => {
    getUsersFromProps();
  };

  const toggleActive = user => () =>
    dispatch(
      updateUser({
        ...user,
        activated: !user.activated,
      })
    );

  const { match } = props;
  const users = useAppSelector(state => state.userManagement.users);
  const loading = useAppSelector(state => state.userManagement.loading);

  // DataGrid
  const columns: GridColDef[] = [
    { field: 'id', headerName: 'ID', width: 90 },
    {
      field: 'fullName',
      headerName: 'Name',
      description: 'This column has a value getter and is not sortable.',
      sortable: false,
      flex: 1,
      valueGetter: (params: { row: { firstName: any; lastName: any; age: any } }) =>
        `${params.row.firstName || ''} ${params.row.lastName || ''} ${params.row.age || ''} `,
    },
    {
      field: 'login',
      headerName: 'Username',
      type: 'string',
      width: 110,
      editable: false,
      resizable: true,
      flex: 1,
    },
    {
      field: 'email',
      headerName: 'Email',
      type: 'string',
      width: 110,
      editable: false,
      flex: 1,
    },
    {
      field: 'activated',
      headerName: 'Status',
      sortable: false,
      width: 150,
      renderCell: (params: { row: IUser }) => (
        <Box>
          {params.row.activated ? (
            <Button color="primary" variant="contained" size="small" onClick={toggleActive(params.row)}>
              <Translate contentKey="userManagement.activated">Activated</Translate>
            </Button>
          ) : (
            <Button color="secondary" variant="contained" size="small" onClick={toggleActive(params.row)}>
              <Translate contentKey="userManagement.deactivated">Deactivated</Translate>
            </Button>
          )}
        </Box>
      ),
    },
    {
      field: 'langKey',
      headerName: 'Language',
      type: 'string',
      width: 110,
      editable: false,
      flex: 1,
    },
    {
      field: 'authorities',
      headerName: 'Authorities',
      sortable: false,
      flex: 1,
      renderCell: (params: { row: IUser }) => (
        <Box py={1}>
          <Stack spacing={1} m={1} direction={'column'}>
            {params.row.authorities
              ? params.row.authorities.map((authority, j) => (
                  <div key={`user-auth-${j}`}>
                    <Chip size="small" label={authority} />
                  </div>
                ))
              : null}
          </Stack>
        </Box>
      ),
    },
    {
      field: 'actions',
      headerName: 'Actions',
      sortable: false,
      width: 150,
      renderCell: (params: { row: IUser }) => (
        <Box>
          <IconButton
            component={self_props => <Link {...self_props} to={`${match.url}/${params.row.login}`} />}
            size="small"
            data-cy="entityEditButton"
          >
            <InfoIcon fontSize="small" />
          </IconButton>
          <IconButton
            component={self_props => <Link {...self_props} to={`${match.url}/${params.row.login}/edit`} />}
            size="small"
            data-cy="entityEditButton"
          >
            <EditIcon fontSize="small" />
          </IconButton>
          <IconButton
            component={self_props => <Link {...self_props} to={`${match.url}/${params.row.login}/delete`} />}
            size="small"
            data-cy="entityDeleteButton"
          >
            <DeleteIcon fontSize="small" />
          </IconButton>
        </Box>
      ),
    },
  ];

  return (
    <SCFPaper className="p-4">
      <Container maxWidth="xl">
        <h2 id="user-management-page-heading" data-cy="userManagementPageHeading">
          <Translate contentKey="userManagement.home.title">Users</Translate>
          <div className="d-flex justify-content-end">
            <Button className="mr-2" color="info" onClick={handleSyncList} disabled={loading}>
              <FontAwesomeIcon icon="sync" spin={loading} />{' '}
              <Translate contentKey="userManagement.home.refreshListLabel">Refresh List</Translate>
            </Button>
            <Link to={`${match.url}/new`} className="btn btn-primary jh-create-entity">
              <FontAwesomeIcon icon="plus" /> <Translate contentKey="userManagement.home.createLabel">Create a new user</Translate>
            </Link>
          </div>
        </h2>
        <div style={{ display: 'flex', height: '100%' }}>
          <div style={{ flexGrow: 1 }}>
            <SCFDataGrid
              rows={users}
              columns={columns}
              pageSize={5}
              rowsPerPageOptions={[5]}
              checkboxSelection
              autoHeight
              disableSelectionOnClick
            />
          </div>
        </div>
      </Container>
    </SCFPaper>
  );
};

export default UserManagement;
