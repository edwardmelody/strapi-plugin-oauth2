import React, { useState, useEffect } from 'react';
import {
  Badge,
  Box,
  Button,
  Typography,
  Table,
  Thead,
  Tbody,
  Tr,
  Th,
  Td,
  IconButton,
  Field,
  Flex,
  Radio,
  Modal,
  Checkbox,
  Combobox,
  ComboboxOption,
  SingleSelect,
  SingleSelectOption,
  Pagination,
  PreviousLink,
  PageLink,
  NextLink,
  Dots,
} from '@strapi/design-system';
import {
  ArrowClockwise,
  Trash,
  Plus,
  Duplicate,
  Eye,
  EyeStriked,
  Pencil,
  Cross,
  ChevronDown,
  ChevronUp,
  Key,
} from '@strapi/icons';
import { useIntl } from 'react-intl';
import { Layouts, Page, useFetchClient, useNotification } from '@strapi/strapi/admin';
import { useNavigate } from 'react-router-dom';
import pluginPermissions from '../permissions';
import qs from 'qs';
import _ from 'lodash';

import { getTranslation } from '../utils/getTranslation';

interface OAuthGlobalSettings {
  documentId: string;
  scopes: string[];
}

interface OAuthClient {
  documentId: string;
  userId: string;
  clientId: string;
  name: string;
  clientType: 'CONFIDENTIAL' | 'PUBLIC';
  createdType: 'BACK_OFFICE' | 'USER';
  scopes: string[];
  redirectUris?: string[];
  meta?: any;
  active: boolean;
  createdAt: string;
  updatedAt: string;
  user: {
    id: number;
    documentId: string;
    username: string;
    email: string;
  };
}

interface CreateClientResponse {
  documentId: string;
  clientId: string;
  clientSecret: string;
  scopes: string[];
  redirectUris?: string[];
  meta?: any;
  user: any;
  publicKey?: string;
  privateKey?: string;
}

interface AvailableScopes {
  [key: string]: Array<{
    action: string;
    name: string;
  }>;
}

interface User {
  documentId: string;
  username: string;
  email: string;
}

interface PaginationMeta {
  page: number;
  pageSize: number;
  pageCount: number;
  total: number;
}

const HomePage = () => {
  const { formatDate } = useIntl();
  const { get, post, put, del } = useFetchClient();
  const { toggleNotification } = useNotification();
  const navigate = useNavigate();

  const [globalSettings, setGlobalSettings] = useState<OAuthGlobalSettings>();
  const [globalLoading, setGlobalLoading] = useState(false);
  const [editGlobalSettings, setEditGlobalSettings] = useState<OAuthGlobalSettings>();
  const [isEditGlobalSettingsModalOpen, setIsEditGlobalSettingsModalOpen] = useState(false);

  const [clients, setClients] = useState<OAuthClient[]>([]);
  const [loading, setLoading] = useState(true);
  const [pagination, setPagination] = useState<PaginationMeta>({
    page: 1,
    pageSize: 10,
    pageCount: 1,
    total: 0,
  });
  const [isCreateModalOpen, setIsCreateModalOpen] = useState(false);
  const [isEditModalOpen, setIsEditModalOpen] = useState(false);
  const [isSecretModalOpen, setIsSecretModalOpen] = useState(false);
  const [editingClient, setEditingClient] = useState<OAuthClient | null>(null);
  const [newClient, setNewClient] = useState<{
    name: string;
    scopes: string[];
    clientType: 'CONFIDENTIAL' | 'PUBLIC';
    redirectUris: string[];
    meta: string;
    userDocumentId: string | null;
  }>({
    name: '',
    scopes: [],
    clientType: 'CONFIDENTIAL',
    redirectUris: [''],
    meta: '',
    userDocumentId: null,
  });
  const [createdSecret, setCreatedSecret] = useState<CreateClientResponse | null>(null);
  const [showSecret, setShowSecret] = useState(false);
  const [availableScopes, setAvailableScopes] = useState<AvailableScopes>({});
  const [users, setUsers] = useState<User[]>([]);
  const [userSearchQuery, setUserSearchQuery] = useState('');
  const [isLoadingUsers, setIsLoadingUsers] = useState(false);
  const [expandedSections, setExpandedSections] = useState<Record<string, boolean>>({});
  const [editExpandedSections, setEditExpandedSections] = useState<Record<string, boolean>>({});
  const [globalExpandedSections, setGlobalExpandedSections] = useState<Record<string, boolean>>({});

  const fetchGlobalSettings = async () => {
    try {
      setGlobalLoading(true);
      const response = await get('/oauth2/global-settings');
      const { data } = response.data;
      setGlobalSettings(data);
    } catch (error) {
      toggleNotification({
        type: 'danger',
        message: 'Failed to fetch global settings',
      });
    } finally {
      setGlobalLoading(false);
    }
  };

  const fetchClients = async (
    page: number = pagination.page,
    pageSize: number = pagination.pageSize
  ) => {
    try {
      setLoading(true);
      const params = qs.stringify(
        {
          populate: ['user'],
          sort: ['createdAt:desc'],
          pagination: {
            page,
            pageSize,
          },
        },
        { encodeValuesOnly: true }
      );
      const response = await get(`/oauth2/clients?${params}`);
      const { data, meta } = response.data;
      setClients(data || []);
      if (meta?.pagination) {
        setPagination(meta.pagination);
      }
    } catch (error) {
      toggleNotification({
        type: 'danger',
        message: 'Failed to fetch OAuth clients',
      });
    } finally {
      setLoading(false);
    }
  };

  const fetchAvailableScopes = async () => {
    try {
      const { data } = await get('/oauth2/scopes');
      setAvailableScopes(data || {});
    } catch (error) {
      toggleNotification({
        type: 'danger',
        message: 'Failed to fetch available scopes',
      });
    }
  };

  const searchUsers = async (query: string) => {
    if (!query || query.length < 2) {
      setUsers([]);
      return;
    }

    try {
      setIsLoadingUsers(true);
      const params = new URLSearchParams({
        filters: JSON.stringify({
          $or: [{ username: { $contains: query } }, { email: { $contains: query } }],
        }),
        sort: 'username:asc',
        pagination: JSON.stringify({ pageSize: 10 }),
      });

      const { data } = await get(
        `/content-manager/collection-types/plugin::users-permissions.user?${params.toString()}`
      );
      setUsers(data?.results || []);
    } catch (error) {
      toggleNotification({
        type: 'danger',
        message: 'Failed to search users',
      });
      setUsers([]);
    } finally {
      setIsLoadingUsers(false);
    }
  };

  useEffect(() => {
    fetchClients();
    fetchAvailableScopes();

    fetchGlobalSettings();
  }, []);

  // Debounce user search
  useEffect(() => {
    const timer = setTimeout(() => {
      searchUsers(userSearchQuery);
    }, 500);

    return () => clearTimeout(timer);
  }, [userSearchQuery]);

  useEffect(() => {
    if (isCreateModalOpen) {
      setNewClient({
        name: '',
        scopes: [],
        clientType: 'CONFIDENTIAL',
        redirectUris: [''],
        meta: '',
        userDocumentId: null,
      });
    }
  }, [isCreateModalOpen]);

  const handleUpdateGlobalSettings = async () => {
    if (!editGlobalSettings) return;

    try {
      await put(`/oauth2/global-settings/${editGlobalSettings.documentId}`, {
        data: {
          scopes: editGlobalSettings.scopes,
        },
      });

      setIsEditGlobalSettingsModalOpen(false);
      setEditGlobalSettings(undefined);
      fetchGlobalSettings();

      toggleNotification({
        type: 'success',
        message: 'Global settings updated successfully',
      });
    } catch (error) {
      toggleNotification({
        type: 'danger',
        message: 'Failed to update Global settings',
      });
    }
  };

  const handleCreateClient = async () => {
    try {
      const meta = newClient.meta ? JSON.parse(newClient.meta) : {};
      const redirectUris = newClient.redirectUris.filter((uri) => uri.trim() !== '');

      const response = await post('/oauth2/clients', {
        data: {
          name: newClient.name,
          scopes: newClient.scopes,
          redirectUris,
          meta,
          user: newClient.userDocumentId,
          clientType: newClient.clientType,
        },
      });
      const { data } = response.data;

      setCreatedSecret(data);
      setIsCreateModalOpen(false);
      setIsSecretModalOpen(true);
      setNewClient({
        name: '',
        scopes: [],
        clientType: 'CONFIDENTIAL',
        redirectUris: [''],
        meta: '',
        userDocumentId: null,
      });
      fetchClients(1, pagination.pageSize);

      toggleNotification({
        type: 'success',
        message: 'OAuth client created successfully',
      });
    } catch (error) {
      toggleNotification({
        type: 'danger',
        message: 'Failed to create OAuth client',
      });
    }
  };

  const handleDeleteClient = async (documentId: string) => {
    if (!confirm('Are you sure you want to delete this client?')) return;

    try {
      await del(`/oauth2/clients/${documentId}`);
      fetchClients(pagination.page, pagination.pageSize);
      toggleNotification({
        type: 'success',
        message: 'OAuth client deleted successfully',
      });
    } catch (error) {
      toggleNotification({
        type: 'danger',
        message: 'Failed to delete OAuth client',
      });
    }
  };

  const handleEditClient = (client: OAuthClient) => {
    console.log('Editing client:', client);
    setEditingClient(client);
    setIsEditModalOpen(true);
  };

  const handleUpdateClient = async () => {
    if (!editingClient) return;

    try {
      const redirectUris = (editingClient.redirectUris || []).filter((uri) => uri.trim() !== '');

      await put(`/oauth2/clients/${editingClient.documentId}`, {
        data: {
          name: editingClient.name,
          scopes: editingClient.scopes,
          redirectUris,
        },
      });

      setIsEditModalOpen(false);
      setEditingClient(null);
      fetchClients(pagination.page, pagination.pageSize);

      toggleNotification({
        type: 'success',
        message: 'OAuth client updated successfully',
      });
    } catch (error) {
      toggleNotification({
        type: 'danger',
        message: 'Failed to update OAuth client',
      });
    }
  };

  const handleRotateSecret = async (documentId: string) => {
    if (!confirm('Are you sure you want to rotate the secret? The old secret will be invalidated.'))
      return;

    try {
      const response = await put(`/oauth2/clients-rotate/${documentId}`);

      const { data } = response.data;

      setCreatedSecret(data);
      setIsSecretModalOpen(true);

      toggleNotification({
        type: 'success',
        message: 'Client secret rotated successfully',
      });
    } catch (error) {
      toggleNotification({
        type: 'danger',
        message: 'Failed to rotate client secret',
      });
    }
  };

  const handleRotateKeypair = async (documentId: string) => {
    if (
      !confirm(
        'Are you sure you want to regenerate the RSA keypair? The old keys will be invalidated.'
      )
    )
      return;

    try {
      const response = await put(`/oauth2/clients-keypair/${documentId}`);

      const { data } = response.data;

      setCreatedSecret(data);
      setIsSecretModalOpen(true);

      toggleNotification({
        type: 'success',
        message: 'RSA keypair regenerated successfully',
      });
    } catch (error) {
      toggleNotification({
        type: 'danger',
        message: 'Failed to regenerate RSA keypair',
      });
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    toggleNotification({
      type: 'success',
      message: 'Copied to clipboard',
    });
  };

  const handleScopeToggle = (scopeName: string) => {
    setNewClient((prev) => ({
      ...prev,
      scopes: prev.scopes.includes(scopeName)
        ? prev.scopes.filter((s) => s !== scopeName)
        : [...prev.scopes, scopeName],
    }));
  };

  const handleSectionToggle = (sectionScopes: Array<{ action: string; name: string }>) => {
    const scopeNames = sectionScopes.map((s) => s.name);
    const allSelected = scopeNames.every((scopeName) => newClient.scopes.includes(scopeName));
    setNewClient((prev) => ({
      ...prev,
      scopes: allSelected
        ? prev.scopes.filter((s) => !scopeNames.includes(s))
        : [...new Set([...prev.scopes, ...scopeNames])],
    }));
  };

  const handleAddRedirectUri = () => {
    setNewClient((prev) => ({
      ...prev,
      redirectUris: [...prev.redirectUris, ''],
    }));
  };

  const handleRemoveRedirectUri = (index: number) => {
    setNewClient((prev) => ({
      ...prev,
      redirectUris: prev.redirectUris.filter((_, i) => i !== index),
    }));
  };

  const handleRedirectUriChange = (index: number, value: string) => {
    setNewClient((prev) => ({
      ...prev,
      redirectUris: prev.redirectUris.map((uri, i) => (i === index ? value : uri)),
    }));
  };

  const handleEditAddRedirectUri = () => {
    if (!editingClient) return;
    setEditingClient({
      ...editingClient,
      redirectUris: [...(editingClient.redirectUris || []), ''],
    });
  };

  const handleEditRemoveRedirectUri = (index: number) => {
    if (!editingClient) return;
    setEditingClient({
      ...editingClient,
      redirectUris: (editingClient.redirectUris || []).filter((_, i) => i !== index),
    });
  };

  const handleEditRedirectUriChange = (index: number, value: string) => {
    if (!editingClient) return;
    setEditingClient({
      ...editingClient,
      redirectUris: (editingClient.redirectUris || []).map((uri, i) => (i === index ? value : uri)),
    });
  };

  const handleEditScopeToggle = (scopeName: string) => {
    if (!editingClient) return;
    setEditingClient({
      ...editingClient,
      scopes: editingClient.scopes.includes(scopeName)
        ? editingClient.scopes.filter((s) => s !== scopeName)
        : [...editingClient.scopes, scopeName],
    });
  };

  const handleEditSectionToggle = (sectionScopes: Array<{ action: string; name: string }>) => {
    if (!editingClient) return;
    const scopeNames = sectionScopes.map((s) => s.name);
    const allSelected = scopeNames.every((scopeName) => editingClient.scopes.includes(scopeName));
    setEditingClient({
      ...editingClient,
      scopes: allSelected
        ? editingClient.scopes.filter((s) => !scopeNames.includes(s))
        : [...new Set([...editingClient.scopes, ...scopeNames])],
    });
  };

  const toggleSectionExpand = (section: string) => {
    setExpandedSections((prev) => ({
      ...prev,
      [section]: !prev[section],
    }));
  };

  const toggleEditSectionExpand = (section: string) => {
    setEditExpandedSections((prev) => ({
      ...prev,
      [section]: !prev[section],
    }));
  };

  const toggleGlobalSectionExpand = (section: string) => {
    setGlobalExpandedSections((prev) => ({
      ...prev,
      [section]: !prev[section],
    }));
  };

  const handlePageChange = (page: number) => {
    fetchClients(page, pagination.pageSize);
  };

  const handlePageSizeChange = (pageSize: string) => {
    fetchClients(1, parseInt(pageSize));
  };

  const handleGlobalScopeToggle = (scopeName: string) => {
    if (!editGlobalSettings) return;
    setEditGlobalSettings({
      ...editGlobalSettings,
      scopes: editGlobalSettings.scopes.includes(scopeName)
        ? editGlobalSettings.scopes.filter((s) => s !== scopeName)
        : [...editGlobalSettings.scopes, scopeName],
    });
  };

  const handleGlobalSectionToggle = (sectionScopes: Array<{ action: string; name: string }>) => {
    if (!editGlobalSettings) return;
    const scopeNames = sectionScopes.map((s) => s.name);
    const allSelected = scopeNames.every((scopeName) =>
      editGlobalSettings.scopes.includes(scopeName)
    );
    setEditGlobalSettings({
      ...editGlobalSettings,
      scopes: allSelected
        ? editGlobalSettings.scopes.filter((s) => !scopeNames.includes(s))
        : [...new Set([...editGlobalSettings.scopes, ...scopeNames])],
    });
  };

  const getPaginationPages = () => {
    const MAX_PAGES = 5;
    const { page: activePage, pageCount } = pagination;
    const pages: number[] = [];

    if (pageCount <= MAX_PAGES) {
      // แสดงทุกหน้าถ้าไม่เกิน MAX_PAGES
      for (let i = 1; i <= pageCount; i++) {
        pages.push(i);
      }
    } else {
      // มีมากกว่า MAX_PAGES
      if (activePage <= 3) {
        // อยู่หน้าแรกๆ แสดง 1,2,3,4,...,pageCount
        pages.push(1, 2, 3, 4, -1, pageCount);
      } else if (activePage >= pageCount - 2) {
        // อยู่หน้าสุดท้าย แสดง 1,...,pageCount-3,pageCount-2,pageCount-1,pageCount
        pages.push(1, -1, pageCount - 3, pageCount - 2, pageCount - 1, pageCount);
      } else {
        // อยู่กลางๆ แสดง 1,...,activePage-1,activePage,activePage+1,...,pageCount
        pages.push(1, -1, activePage - 1, activePage, activePage + 1, -2, pageCount);
      }
    }

    return pages;
  };

  return (
    <Layouts.Root>
      <Page.Title>OAuth2 Clients</Page.Title>
      <Page.Main>
        <Layouts.Header title="OAuth2 Clients" subtitle={`${pagination.total} client(s) found`} />
        <Layouts.Content>
          <Flex justifyContent="space-between" marginBottom={4}>
            <Typography variant="beta">OAuth2 Global Scopes Settings</Typography>
            <Button
              startIcon={<Pencil />}
              onClick={() => {
                setEditGlobalSettings(globalSettings);
                setIsEditGlobalSettingsModalOpen(true);
              }}
            >
              Edit
            </Button>
          </Flex>

          {globalLoading ? (
            <Typography>Loading...</Typography>
          ) : (globalSettings?.scopes?.length || 0) > 0 ? (
            <Box padding={4} background="neutral0" hasRadius marginBottom={6}>
              <Flex direction="row" gap={3} wrap="wrap" alignItems="flex-start">
                {Object.entries(availableScopes).map(([section, scopes]) => {
                  const selectedScopesInSection = scopes.filter((scope) =>
                    (globalSettings?.scopes || []).includes(scope.name)
                  );

                  if (selectedScopesInSection.length === 0) return null;

                  return (
                    <Box key={section} width="48%" minWidth="250px">
                      <Flex direction="column" gap={2} alignItems="flex-start">
                        <Typography fontWeight="bold" variant="omega">
                          {section} ({selectedScopesInSection.length})
                        </Typography>
                        <Box paddingLeft={6}>
                          <Flex direction="column" gap={2} alignItems="flex-start">
                            {selectedScopesInSection.map((scope) => (
                              <Flex key={scope.name} gap={2} alignItems="center">
                                <Box
                                  paddingLeft={2}
                                  paddingRight={2}
                                  paddingTop={1}
                                  paddingBottom={1}
                                  background={
                                    scope.action.includes('find') ||
                                    scope.action.includes('get') ||
                                    scope.action.includes('list')
                                      ? 'success500'
                                      : scope.action.includes('update')
                                        ? 'warning500'
                                        : scope.action.includes('delete') ||
                                            scope.action.includes('remove') ||
                                            scope.action.includes('destroy')
                                          ? 'danger500'
                                          : 'primary500'
                                  }
                                  hasRadius
                                >
                                  <Typography variant="pi" fontWeight="bold" fontSize={1}>
                                    {scope.action}
                                  </Typography>
                                </Box>
                                <Typography variant="pi" fontFamily="monospace">
                                  {scope.name}
                                </Typography>
                              </Flex>
                            ))}
                          </Flex>
                        </Box>
                      </Flex>
                    </Box>
                  );
                })}
              </Flex>
            </Box>
          ) : (
            <Box padding={4} background="neutral0" hasRadius marginBottom={6}>
              <Typography>No global scopes configured.</Typography>
            </Box>
          )}

          <Flex justifyContent="space-between" marginBottom={4}>
            <Flex direction="column" gap={1} alignItems="flex-start">
              <Typography variant="beta">OAuth2 Clients</Typography>
              {pagination.total > 0 && (
                <Typography variant="pi" textColor="neutral600">
                  {pagination.total} client(s) found
                </Typography>
              )}
            </Flex>
            <Flex gap={2}>
              <Button
                variant="secondary"
                startIcon={<Key />}
                onClick={() => navigate('access-tokens')}
                persmission={pluginPermissions.readAccessTokens}
              >
                View All Access Tokens
              </Button>
              <Button startIcon={<Plus />} onClick={() => setIsCreateModalOpen(true)}>
                Create Client
              </Button>
            </Flex>
          </Flex>

          {loading ? (
            <Typography>Loading...</Typography>
          ) : (
            <Table>
              <Thead>
                <Tr>
                  <Th>
                    <Typography variant="sigma">Name</Typography>
                  </Th>
                  <Th>
                    <Typography variant="sigma">User ID</Typography>
                  </Th>
                  <Th>
                    <Typography variant="sigma">Client ID</Typography>
                  </Th>
                  <Th>
                    <Typography variant="sigma">Scopes</Typography>
                  </Th>
                  <Th>
                    <Typography variant="sigma">Client Type</Typography>
                  </Th>
                  <Th>
                    <Typography variant="sigma">Created By</Typography>
                  </Th>
                  <Th>
                    <Typography variant="sigma">Status</Typography>
                  </Th>
                  <Th>
                    <Typography variant="sigma">Updated</Typography>
                  </Th>
                  <Th>
                    <Typography variant="sigma">Created</Typography>
                  </Th>
                  <Th>
                    <Typography variant="sigma">Actions</Typography>
                  </Th>
                </Tr>
              </Thead>
              <Tbody>
                {clients.map((client) => (
                  <Tr key={client.documentId}>
                    <Td
                      style={{
                        verticalAlign: 'top',
                      }}
                    >
                      <Box style={{ marginTop: '21px' }}>
                        <Typography>{client.name}</Typography>
                      </Box>
                    </Td>
                    <Td
                      style={{
                        verticalAlign: client.createdType === 'BACK_OFFICE' ? 'top' : 'center',
                      }}
                    >
                      <Flex gap={2} alignItems="center">
                        <Typography fontFamily="monospace">{client.user.documentId}</Typography>
                        <IconButton
                          onClick={() => copyToClipboard(client.user.documentId)}
                          label="Copy"
                          size="S"
                          withTooltip={false}
                        >
                          <Duplicate />
                        </IconButton>
                      </Flex>
                    </Td>
                    <Td
                      style={{
                        verticalAlign: client.createdType === 'BACK_OFFICE' ? 'top' : 'center',
                      }}
                    >
                      <Flex gap={2} alignItems="center">
                        <Typography fontFamily="monospace">{client.clientId}</Typography>
                        <IconButton
                          onClick={() => copyToClipboard(client.clientId)}
                          label="Copy"
                          size="S"
                          withTooltip={false}
                        >
                          <Duplicate />
                        </IconButton>
                      </Flex>
                    </Td>
                    <Td
                      style={{
                        verticalAlign: client.createdType === 'BACK_OFFICE' ? 'top' : 'center',
                      }}
                    >
                      {client.createdType === 'BACK_OFFICE' ? (
                        (client.scopes || []).map((scope, index) => (
                          <Box key={index}>
                            <Typography>{scope}</Typography>
                          </Box>
                        ))
                      ) : (
                        <Typography style={{ fontSize: '100%' }}>
                          Follow by Global Scopes Settings
                        </Typography>
                      )}
                    </Td>
                    <Td
                      style={{
                        verticalAlign: client.createdType === 'BACK_OFFICE' ? 'top' : 'center',
                      }}
                    >
                      <Typography>{_.capitalize(client.clientType.toLowerCase())}</Typography>
                    </Td>
                    <Td
                      style={{
                        verticalAlign: client.createdType === 'BACK_OFFICE' ? 'top' : 'center',
                      }}
                    >
                      <Typography>{_.capitalize(client.createdType.toLowerCase())}</Typography>
                    </Td>
                    <Td
                      style={{
                        verticalAlign: client.createdType === 'BACK_OFFICE' ? 'top' : 'center',
                      }}
                    >
                      {client.active ? <Badge active>Active</Badge> : <Badge>Inactive</Badge>}
                    </Td>
                    <Td
                      style={{
                        verticalAlign: client.createdType === 'BACK_OFFICE' ? 'top' : 'center',
                      }}
                    >
                      <Typography>
                        {formatDate(client.updatedAt, {
                          year: 'numeric',
                          month: 'short',
                          day: '2-digit',
                          hour: '2-digit',
                          minute: '2-digit',
                        })}
                      </Typography>
                    </Td>
                    <Td
                      style={{
                        verticalAlign: client.createdType === 'BACK_OFFICE' ? 'top' : 'center',
                      }}
                    >
                      <Typography>
                        {formatDate(client.createdAt, {
                          year: 'numeric',
                          month: 'short',
                          day: '2-digit',
                          hour: '2-digit',
                          minute: '2-digit',
                        })}
                      </Typography>
                    </Td>
                    <Td
                      style={{
                        verticalAlign: client.createdType === 'BACK_OFFICE' ? 'top' : 'center',
                      }}
                    >
                      <Flex gap={1}>
                        <IconButton
                          label="View Access Tokens"
                          onClick={() => navigate(`access-tokens/${client.documentId}`)}
                          variant="tertiary"
                          persmission={pluginPermissions.readAccessTokens}
                          withTooltip={false}
                        >
                          <Key />
                        </IconButton>
                        <IconButton
                          label="Edit"
                          onClick={() => handleEditClient(client)}
                          variant="tertiary"
                          permission={pluginPermissions.updateGlobalSettings}
                          withTooltip={false}
                        >
                          <Pencil />
                        </IconButton>
                        <IconButton
                          label="Regenerate Secret"
                          onClick={() => handleRotateSecret(client.documentId)}
                          variant="secondary"
                          permission={pluginPermissions.rotateClient}
                          withTooltip={false}
                        >
                          <ArrowClockwise />
                        </IconButton>
                        <IconButton
                          label="Regenerate RSA Keypair"
                          onClick={() => handleRotateKeypair(client.documentId)}
                          variant="secondary"
                          permission={pluginPermissions.generateClientKeyPair}
                          withTooltip={false}
                        >
                          <Key />
                        </IconButton>
                        <IconButton
                          label="Delete"
                          onClick={() => handleDeleteClient(client.documentId)}
                          variant="danger-light"
                          permission={pluginPermissions.deleteClient}
                          withTooltip={false}
                        >
                          <Trash />
                        </IconButton>
                      </Flex>
                    </Td>
                  </Tr>
                ))}
              </Tbody>
            </Table>
          )}

          {!loading && (
            <Box marginTop={4}>
              <Flex justifyContent="space-between" alignItems="center">
                <SingleSelect
                  size="S"
                  value={pagination.pageSize.toString()}
                  onChange={handlePageSizeChange}
                  placeholder="Page size"
                >
                  <SingleSelectOption value="10">10 per page</SingleSelectOption>
                  <SingleSelectOption value="25">25 per page</SingleSelectOption>
                  <SingleSelectOption value="50">50 per page</SingleSelectOption>
                  <SingleSelectOption value="100">100 per page</SingleSelectOption>
                </SingleSelect>

                <Pagination
                  activePage={pagination.page}
                  pageCount={pagination.pageCount}
                  onPageChange={handlePageChange}
                >
                  <PreviousLink
                    onClick={() => pagination.page > 1 && handlePageChange(pagination.page - 1)}
                  >
                    Go to previous page
                  </PreviousLink>
                  {getPaginationPages().map((pageNum, index) => {
                    if (pageNum === -1 || pageNum === -2) {
                      return <Dots key={`dots-${index}`}>...</Dots>;
                    }
                    return (
                      <PageLink
                        key={pageNum}
                        number={pageNum}
                        onClick={() => handlePageChange(pageNum)}
                      >
                        Go to page {pageNum}
                      </PageLink>
                    );
                  })}
                  <NextLink
                    onClick={() =>
                      pagination.page < pagination.pageCount &&
                      handlePageChange(pagination.page + 1)
                    }
                  >
                    Go to next page
                  </NextLink>
                </Pagination>
              </Flex>
            </Box>
          )}

          {/* Edit Global Settings Modal */}
          <Modal.Root
            open={isEditGlobalSettingsModalOpen}
            onOpenChange={setIsEditGlobalSettingsModalOpen}
          >
            <Modal.Content>
              <Modal.Header>
                <Modal.Title>Edit Global OAuth Scopes</Modal.Title>
              </Modal.Header>
              <Modal.Body>
                {editGlobalSettings && (
                  <Flex direction="column" gap={4} width="100%">
                    <Field.Root required width="100%">
                      <Flex justifyContent="space-between" alignItems="center" marginBottom={2}>
                        <Field.Label>Scopes</Field.Label>
                        <Flex gap={2}>
                          <Button
                            variant="tertiary"
                            size="S"
                            onClick={() => {
                              const allScopeNames = Object.values(availableScopes)
                                .flat()
                                .map((s) => s.name);
                              setEditGlobalSettings({
                                ...editGlobalSettings,
                                scopes: allScopeNames,
                              });
                            }}
                          >
                            Select All
                          </Button>
                          <Button
                            variant="tertiary"
                            size="S"
                            onClick={() =>
                              setEditGlobalSettings({ ...editGlobalSettings, scopes: [] })
                            }
                          >
                            Deselect All
                          </Button>
                        </Flex>
                      </Flex>
                      <Box
                        maxHeight="300px"
                        width="100%"
                        overflow="auto"
                        padding={3}
                        background="neutral100"
                        hasRadius
                      >
                        <Flex direction="row" gap={3} wrap="wrap" alignItems="flex-start">
                          {Object.entries(availableScopes).map(([section, scopes]) => {
                            const scopeNames = scopes.map((s) => s.name);
                            const allSelected = scopeNames.every((scopeName) =>
                              editGlobalSettings.scopes.includes(scopeName)
                            );

                            const isExpanded = globalExpandedSections[section];
                            return (
                              <Box key={section} width="48%" minWidth="250px">
                                <Flex direction="column" gap={2} alignItems="flex-start">
                                  <Flex gap={2} alignItems="center" width="100%">
                                    <Checkbox
                                      checked={allSelected}
                                      onCheckedChange={() => handleGlobalSectionToggle(scopes)}
                                    >
                                      <Typography fontWeight="bold" variant="omega">
                                        {section} ({scopes.length})
                                      </Typography>
                                    </Checkbox>
                                    <IconButton
                                      onClick={() => toggleGlobalSectionExpand(section)}
                                      label={isExpanded ? 'Collapse' : 'Expand'}
                                      variant="ghost"
                                      size="S"
                                      withTooltip={false}
                                    >
                                      {isExpanded ? <ChevronUp /> : <ChevronDown />}
                                    </IconButton>
                                  </Flex>
                                  {isExpanded && (
                                    <Box paddingLeft={6}>
                                      <Flex direction="column" gap={2} alignItems="flex-start">
                                        {scopes.map((scope) => (
                                          <Checkbox
                                            key={scope.name}
                                            checked={editGlobalSettings.scopes.includes(scope.name)}
                                            onCheckedChange={() =>
                                              handleGlobalScopeToggle(scope.name)
                                            }
                                          >
                                            <Flex gap={2} alignItems="center">
                                              <Box
                                                paddingLeft={2}
                                                paddingRight={2}
                                                paddingTop={1}
                                                paddingBottom={1}
                                                background={
                                                  scope.action.includes('find') ||
                                                  scope.action.includes('get') ||
                                                  scope.action.includes('list')
                                                    ? 'success500'
                                                    : scope.action.includes('update')
                                                      ? 'warning500'
                                                      : scope.action.includes('delete') ||
                                                          scope.action.includes('remove') ||
                                                          scope.action.includes('destroy')
                                                        ? 'danger500'
                                                        : 'primary500'
                                                }
                                                hasRadius
                                              >
                                                <Typography
                                                  variant="pi"
                                                  fontWeight="bold"
                                                  fontSize={1}
                                                >
                                                  {scope.action}
                                                </Typography>
                                              </Box>
                                              <Typography variant="pi" fontFamily="monospace">
                                                {scope.name}
                                              </Typography>
                                            </Flex>
                                          </Checkbox>
                                        ))}
                                      </Flex>
                                    </Box>
                                  )}
                                </Flex>
                              </Box>
                            );
                          })}
                        </Flex>
                      </Box>
                      <Field.Hint>Selected: {editGlobalSettings.scopes.length} scope(s)</Field.Hint>
                    </Field.Root>
                  </Flex>
                )}
              </Modal.Body>
              <Modal.Footer>
                <Modal.Close>
                  <Button variant="tertiary">Cancel</Button>
                </Modal.Close>
                <Button onClick={handleUpdateGlobalSettings} disabled={!editGlobalSettings}>
                  Update
                </Button>
              </Modal.Footer>
            </Modal.Content>
          </Modal.Root>

          {/* Create Client Modal */}
          <Modal.Root open={isCreateModalOpen} onOpenChange={setIsCreateModalOpen}>
            <Modal.Content>
              <Modal.Header>
                <Modal.Title>Create OAuth Client</Modal.Title>
              </Modal.Header>
              <Modal.Body>
                <Flex direction="column" gap={4} width="100%">
                  <Field.Root required width="100%">
                    <Field.Label>Name</Field.Label>
                    <Field.Input
                      value={newClient.name}
                      onChange={(e: React.ChangeEvent<HTMLInputElement>) =>
                        setNewClient({ ...newClient, name: e.target.value })
                      }
                      placeholder="My Application"
                    />
                  </Field.Root>

                  <Field.Root required width="100%">
                    <Field.Label>User</Field.Label>
                    <Combobox
                      value={newClient.userDocumentId}
                      onChange={(value: string) =>
                        setNewClient({ ...newClient, userDocumentId: value })
                      }
                      onInputChange={(e: React.ChangeEvent<HTMLInputElement>) =>
                        setUserSearchQuery(e.target.value)
                      }
                      placeholder="Type to search users..."
                      loading={isLoadingUsers}
                    >
                      {users.length === 0 && userSearchQuery.length >= 2 && !isLoadingUsers ? (
                        <ComboboxOption value="" disabled>
                          No users found
                        </ComboboxOption>
                      ) : (
                        users.map((user) => (
                          <ComboboxOption key={user.documentId} value={user.documentId}>
                            {user.username} ({user.email})
                          </ComboboxOption>
                        ))
                      )}
                    </Combobox>
                    {userSearchQuery.length > 0 && userSearchQuery.length < 2 && (
                      <Field.Hint>Type at least 2 characters to search</Field.Hint>
                    )}
                  </Field.Root>

                  <Field.Root required width="100%">
                    <Radio.Group
                      defaultValue={newClient.clientType}
                      aria-label="Theme"
                      onValueChange={(value: 'CONFIDENTIAL' | 'PUBLIC') =>
                        setNewClient({ ...newClient, clientType: value })
                      }
                    >
                      <Radio.Item value="CONFIDENTIAL">Confidential</Radio.Item>
                      <Radio.Item value="PUBLIC">Public</Radio.Item>
                    </Radio.Group>
                  </Field.Root>

                  <Field.Root width="100%">
                    <Field.Label>Redirect URIs</Field.Label>
                    <Flex direction="column" gap={2} alignItems="flex-start" width="100%">
                      {(newClient.redirectUris || []).map((uri, index) => (
                        <Flex key={index} gap={2} alignItems="flex-end" width="50%">
                          <Box flex="1">
                            <Field.Input
                              value={uri}
                              onChange={(e: React.ChangeEvent<HTMLInputElement>) =>
                                handleRedirectUriChange(index, e.target.value)
                              }
                              placeholder="https://example.com/callback"
                            />
                          </Box>
                          {newClient.redirectUris?.length > 1 && (
                            <IconButton
                              label="Remove"
                              onClick={() => handleRemoveRedirectUri(index)}
                              variant="danger-light"
                              withTooltip={false}
                            >
                              <Cross />
                            </IconButton>
                          )}
                        </Flex>
                      ))}
                      <Button
                        variant="secondary"
                        startIcon={<Plus />}
                        onClick={handleAddRedirectUri}
                        size="S"
                      >
                        Add Redirect URI
                      </Button>
                    </Flex>
                    <Field.Hint>Authorization callback URLs for OAuth flow</Field.Hint>
                  </Field.Root>

                  <Field.Root required width="100%">
                    <Flex justifyContent="space-between" alignItems="center" marginBottom={2}>
                      <Field.Label>Scopes</Field.Label>
                      <Flex gap={2}>
                        <Button
                          variant="tertiary"
                          size="S"
                          onClick={() => {
                            const allScopeNames = Object.values(availableScopes)
                              .flat()
                              .map((s) => s.name);
                            setNewClient({ ...newClient, scopes: allScopeNames });
                          }}
                        >
                          Select All
                        </Button>
                        <Button
                          variant="tertiary"
                          size="S"
                          onClick={() => setNewClient({ ...newClient, scopes: [] })}
                        >
                          Deselect All
                        </Button>
                      </Flex>
                    </Flex>
                    <Box
                      maxHeight="300px"
                      width="100%"
                      overflow="auto"
                      padding={3}
                      background="neutral100"
                      hasRadius
                    >
                      <Flex direction="row" gap={3} wrap="wrap" alignItems="flex-start">
                        {Object.entries(availableScopes).map(([section, scopes]) => {
                          const scopeNames = scopes.map((s) => s.name);
                          const allSelected = scopeNames.every((scopeName) =>
                            newClient.scopes.includes(scopeName)
                          );

                          const isExpanded = expandedSections[section];
                          return (
                            <Box key={section} width="48%" minWidth="250px">
                              <Flex direction="column" gap={2} alignItems="flex-start">
                                <Flex gap={2} alignItems="center" width="100%">
                                  <Checkbox
                                    checked={allSelected}
                                    onCheckedChange={() => handleSectionToggle(scopes)}
                                  >
                                    <Typography fontWeight="bold" variant="omega">
                                      {section} ({scopes.length})
                                    </Typography>
                                  </Checkbox>
                                  <IconButton
                                    onClick={() => toggleSectionExpand(section)}
                                    label={isExpanded ? 'Collapse' : 'Expand'}
                                    variant="ghost"
                                    size="S"
                                    withTooltip={false}
                                  >
                                    {isExpanded ? <ChevronUp /> : <ChevronDown />}
                                  </IconButton>
                                </Flex>
                                {isExpanded && (
                                  <Box paddingLeft={6}>
                                    <Flex direction="column" gap={2} alignItems="flex-start">
                                      {scopes.map((scope) => (
                                        <Checkbox
                                          key={scope.name}
                                          checked={newClient.scopes.includes(scope.name)}
                                          onCheckedChange={() => handleScopeToggle(scope.name)}
                                        >
                                          <Flex gap={2} alignItems="center">
                                            <Box
                                              paddingLeft={2}
                                              paddingRight={2}
                                              paddingTop={1}
                                              paddingBottom={1}
                                              background={
                                                scope.action.includes('find') ||
                                                scope.action.includes('get') ||
                                                scope.action.includes('list')
                                                  ? 'success500'
                                                  : scope.action.includes('update')
                                                    ? 'warning500'
                                                    : scope.action.includes('delete') ||
                                                        scope.action.includes('remove') ||
                                                        scope.action.includes('destroy')
                                                      ? 'danger500'
                                                      : 'primary500'
                                              }
                                              hasRadius
                                            >
                                              <Typography
                                                variant="pi"
                                                fontWeight="bold"
                                                fontSize={1}
                                              >
                                                {scope.action}
                                              </Typography>
                                            </Box>
                                            <Typography variant="pi" fontFamily="monospace">
                                              {scope.name}
                                            </Typography>
                                          </Flex>
                                        </Checkbox>
                                      ))}
                                    </Flex>
                                  </Box>
                                )}
                              </Flex>
                            </Box>
                          );
                        })}
                      </Flex>
                    </Box>
                    <Field.Hint>Selected: {newClient.scopes.length} scope(s)</Field.Hint>
                  </Field.Root>

                  {/* <Field.Root width="100%">
                  <Field.Label>Metadata (JSON)</Field.Label>
                  <Textarea
                    value={newClient.meta}
                    onChange={(e: React.ChangeEvent<HTMLTextAreaElement>) =>
                      setNewClient({ ...newClient, meta: e.target.value })
                    }
                    placeholder='{"key": "value"}'
                  />
                </Field.Root> */}
                </Flex>
              </Modal.Body>
              <Modal.Footer>
                <Modal.Close>
                  <Button variant="tertiary">Cancel</Button>
                </Modal.Close>
                <Button
                  onClick={handleCreateClient}
                  disabled={
                    !newClient.name || newClient.scopes.length === 0 || !newClient.userDocumentId
                  }
                  permission={pluginPermissions.createClient}
                >
                  Create
                </Button>
              </Modal.Footer>
            </Modal.Content>
          </Modal.Root>

          {/* Secret Display Modal */}
          <Modal.Root open={isSecretModalOpen} onOpenChange={setIsSecretModalOpen}>
            <Modal.Content>
              <Modal.Header>
                <Modal.Title>Client Credentials</Modal.Title>
              </Modal.Header>
              <Modal.Body>
                {createdSecret && (
                  <Box
                    background="neutral100"
                    padding={4}
                    hasRadius
                    borderColor="neutral200"
                    borderStyle="solid"
                    borderWidth="1px"
                  >
                    <Typography variant="pi" fontWeight="bold" marginBottom={2}>
                      ⚠️ Save these credentials now! They will not be shown again.
                    </Typography>
                    <Flex direction="column" gap={3} marginTop={3} alignItems="flex-start">
                      <Box width="100%">
                        <Typography variant="sigma">User ID:</Typography>
                        <Flex gap={2} alignItems="center" marginTop={1}>
                          <Typography fontFamily="monospace" fontSize={2}>
                            {createdSecret.user.documentId}
                          </Typography>
                          <IconButton
                            onClick={() => copyToClipboard(createdSecret.user.documentId)}
                            label="Copy"
                            size="S"
                            withTooltip={false}
                          >
                            <Duplicate />
                          </IconButton>
                        </Flex>
                      </Box>
                      <Box width="100%">
                        <Typography variant="sigma">Client ID:</Typography>
                        <Flex gap={2} alignItems="center" marginTop={1}>
                          <Typography fontFamily="monospace" fontSize={2}>
                            {createdSecret.clientId}
                          </Typography>
                          <IconButton
                            onClick={() => copyToClipboard(createdSecret.clientId)}
                            label="Copy"
                            size="S"
                            withTooltip={false}
                          >
                            <Duplicate />
                          </IconButton>
                        </Flex>
                      </Box>
                      {createdSecret.clientSecret && (
                        <Box width="100%">
                          <Typography variant="sigma">Client Secret:</Typography>
                          <Flex gap={2} alignItems="center" marginTop={1}>
                            <Typography fontFamily="monospace" fontSize={2}>
                              {showSecret
                                ? createdSecret.clientSecret
                                : Array(createdSecret.clientSecret.length).fill('•').join('')}
                            </Typography>
                            <IconButton
                              onClick={() => setShowSecret(!showSecret)}
                              label={showSecret ? 'Hide' : 'Show'}
                              size="S"
                              withTooltip={false}
                            >
                              {showSecret ? <EyeStriked /> : <Eye />}
                            </IconButton>
                            <IconButton
                              onClick={() => copyToClipboard(createdSecret.clientSecret)}
                              label="Copy"
                              size="S"
                              withTooltip={false}
                            >
                              <Duplicate />
                            </IconButton>
                          </Flex>
                        </Box>
                      )}
                      {createdSecret.privateKey && (
                        <Box width="100%">
                          <Flex justifyContent="space-between" alignItems="center">
                            <Typography variant="sigma">Public Key:</Typography>
                            <IconButton
                              onClick={() => copyToClipboard(createdSecret.publicKey!)}
                              label="Copy"
                              size="S"
                              withTooltip={false}
                            >
                              <Duplicate />
                            </IconButton>
                          </Flex>
                          <Box
                            marginTop={1}
                            padding={3}
                            background="neutral0"
                            hasRadius
                            borderColor="neutral200"
                            borderStyle="solid"
                            borderWidth="1px"
                          >
                            <Typography
                              fontFamily="monospace"
                              fontSize={1}
                              style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}
                            >
                              {createdSecret.publicKey}
                            </Typography>
                          </Box>
                        </Box>
                      )}
                      {createdSecret.privateKey && (
                        <Box width="100%">
                          <Flex justifyContent="space-between" alignItems="center">
                            <Typography variant="sigma">Private Key:</Typography>
                            <IconButton
                              onClick={() => copyToClipboard(createdSecret.privateKey!)}
                              label="Copy"
                              size="S"
                              withTooltip={false}
                            >
                              <Duplicate />
                            </IconButton>
                          </Flex>
                          <Box
                            marginTop={1}
                            padding={3}
                            background="neutral0"
                            hasRadius
                            borderColor="neutral200"
                            borderStyle="solid"
                            borderWidth="1px"
                          >
                            <Typography
                              fontFamily="monospace"
                              fontSize={1}
                              style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}
                            >
                              {createdSecret.privateKey}
                            </Typography>
                          </Box>
                        </Box>
                      )}
                    </Flex>
                  </Box>
                )}
              </Modal.Body>
              <Modal.Footer>
                <Modal.Close>
                  <Button variant="secondary">Close</Button>
                </Modal.Close>
              </Modal.Footer>
            </Modal.Content>
          </Modal.Root>

          {/* Edit Client Modal */}
          <Modal.Root open={isEditModalOpen} onOpenChange={setIsEditModalOpen}>
            <Modal.Content>
              <Modal.Header>
                <Modal.Title>Edit OAuth Client</Modal.Title>
              </Modal.Header>
              <Modal.Body>
                {editingClient && (
                  <Flex direction="column" gap={4} width="100%">
                    <Field.Root width="100%">
                      <Field.Label>Name</Field.Label>
                      <Field.Input value={editingClient.name} />
                    </Field.Root>

                    <Field.Root width="100%">
                      <Field.Label>User</Field.Label>
                      <Field.Input
                        value={`${editingClient.user.username} (${editingClient.user.email})`}
                        disabled
                      />
                    </Field.Root>

                    <Field.Root width="100%">
                      <Field.Label>Redirect URIs</Field.Label>
                      <Flex direction="column" gap={2} alignItems="flex-start" width="100%">
                        {(editingClient.redirectUris || []).map((uri, index) => (
                          <Flex key={index} gap={2} alignItems="center" width="50%">
                            <Box flex="1">
                              <Field.Input
                                value={uri}
                                onChange={(e: React.ChangeEvent<HTMLInputElement>) =>
                                  handleEditRedirectUriChange(index, e.target.value)
                                }
                                placeholder="https://example.com/callback"
                              />
                            </Box>
                            {(editingClient.redirectUris || []).length > 0 && (
                              <IconButton
                                label="Remove"
                                onClick={() => handleEditRemoveRedirectUri(index)}
                                variant="danger-light"
                                withTooltip={false}
                              >
                                <Cross />
                              </IconButton>
                            )}
                          </Flex>
                        ))}
                        <Button
                          variant="secondary"
                          startIcon={<Plus />}
                          onClick={handleEditAddRedirectUri}
                          size="S"
                        >
                          Add Redirect URI
                        </Button>
                      </Flex>
                      <Field.Hint>Authorization callback URLs for OAuth flow</Field.Hint>
                    </Field.Root>

                    <Field.Root required width="100%">
                      <Flex justifyContent="space-between" alignItems="center" marginBottom={2}>
                        <Field.Label>Scopes</Field.Label>
                        <Flex gap={2}>
                          <Button
                            variant="tertiary"
                            size="S"
                            onClick={() => {
                              const allScopeNames = Object.values(availableScopes)
                                .flat()
                                .map((s) => s.name);
                              setEditingClient({ ...editingClient!, scopes: allScopeNames });
                            }}
                          >
                            Select All
                          </Button>
                          <Button
                            variant="tertiary"
                            size="S"
                            onClick={() => setEditingClient({ ...editingClient!, scopes: [] })}
                          >
                            Deselect All
                          </Button>
                        </Flex>
                      </Flex>
                      <Box
                        maxHeight="300px"
                        width="100%"
                        overflow="auto"
                        padding={3}
                        background="neutral100"
                        hasRadius
                      >
                        <Flex direction="row" gap={3} wrap="wrap" alignItems="flex-start">
                          {Object.entries(availableScopes).map(([section, scopes]) => {
                            const scopeNames = scopes.map((s) => s.name);
                            const allSelected = scopeNames.every((scopeName) =>
                              editingClient.scopes.includes(scopeName)
                            );

                            const isExpanded = editExpandedSections[section];
                            return (
                              <Box key={section} width="48%" minWidth="250px">
                                <Flex direction="column" gap={2} alignItems="flex-start">
                                  <Flex gap={2} alignItems="center" width="100%">
                                    <Checkbox
                                      checked={allSelected}
                                      onCheckedChange={() => handleEditSectionToggle(scopes)}
                                    >
                                      <Typography fontWeight="bold" variant="omega">
                                        {section} ({scopes.length})
                                      </Typography>
                                    </Checkbox>
                                    <IconButton
                                      onClick={() => toggleEditSectionExpand(section)}
                                      label={isExpanded ? 'Collapse' : 'Expand'}
                                      variant="ghost"
                                      size="S"
                                      withTooltip={false}
                                    >
                                      {isExpanded ? <ChevronUp /> : <ChevronDown />}
                                    </IconButton>
                                  </Flex>
                                  {isExpanded && (
                                    <Box paddingLeft={6}>
                                      <Flex direction="column" gap={2} alignItems="flex-start">
                                        {scopes.map((scope) => (
                                          <Checkbox
                                            key={scope.name}
                                            checked={editingClient.scopes.includes(scope.name)}
                                            onCheckedChange={() =>
                                              handleEditScopeToggle(scope.name)
                                            }
                                          >
                                            <Flex gap={2} alignItems="center">
                                              <Box
                                                paddingLeft={2}
                                                paddingRight={2}
                                                paddingTop={1}
                                                paddingBottom={1}
                                                background={
                                                  scope.action.includes('find') ||
                                                  scope.action.includes('get') ||
                                                  scope.action.includes('list')
                                                    ? 'success500'
                                                    : scope.action.includes('update')
                                                      ? 'warning500'
                                                      : scope.action.includes('delete') ||
                                                          scope.action.includes('remove') ||
                                                          scope.action.includes('destroy')
                                                        ? 'danger500'
                                                        : 'primary500'
                                                }
                                                hasRadius
                                              >
                                                <Typography
                                                  variant="pi"
                                                  fontWeight="bold"
                                                  fontSize={1}
                                                >
                                                  {scope.action}
                                                </Typography>
                                              </Box>
                                              <Typography variant="pi" fontFamily="monospace">
                                                {scope.name}
                                              </Typography>
                                            </Flex>
                                          </Checkbox>
                                        ))}
                                      </Flex>
                                    </Box>
                                  )}
                                </Flex>
                              </Box>
                            );
                          })}
                        </Flex>
                      </Box>
                      <Field.Hint>Selected: {editingClient.scopes.length} scope(s)</Field.Hint>
                    </Field.Root>
                  </Flex>
                )}
              </Modal.Body>
              <Modal.Footer>
                <Modal.Close>
                  <Button variant="tertiary">Cancel</Button>
                </Modal.Close>
                <Button
                  onClick={handleUpdateClient}
                  disabled={!editingClient || editingClient.scopes.length === 0}
                  permission={pluginPermissions.updateClient}
                >
                  Update
                </Button>
              </Modal.Footer>
            </Modal.Content>
          </Modal.Root>
        </Layouts.Content>
      </Page.Main>
    </Layouts.Root>
  );
};

export { HomePage };
