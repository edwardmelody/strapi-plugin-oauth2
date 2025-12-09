"use strict";
Object.defineProperty(exports, Symbol.toStringTag, { value: "Module" });
const jsxRuntime = require("react/jsx-runtime");
const admin = require("@strapi/strapi/admin");
const reactRouterDom = require("react-router-dom");
const react = require("react");
const designSystem = require("@strapi/design-system");
const icons = require("@strapi/icons");
const reactIntl = require("react-intl");
const qs = require("qs");
const _ = require("lodash");
const _interopDefault = (e) => e && e.__esModule ? e : { default: e };
const qs__default = /* @__PURE__ */ _interopDefault(qs);
const ___default = /* @__PURE__ */ _interopDefault(_);
const pluginPermissions = {
  updateGlobalSettings: [
    { action: "plugin::strapi-plugin-oauth2.oauth-global-setting.update", subject: null }
  ],
  createClient: [{ action: "plugin::strapi-plugin-oauth2.oauth-client.create", subject: null }],
  rotateClient: [{ action: "plugin::strapi-plugin-oauth2.oauth-client.rotate", subject: null }],
  updateClient: [{ action: "plugin::strapi-plugin-oauth2.oauth-client.update", subject: null }],
  deleteClient: [{ action: "plugin::strapi-plugin-oauth2.oauth-client.delete", subject: null }],
  readAccessTokens: [
    { action: "plugin::strapi-plugin-oauth2.oauth-access-token.read", subject: null }
  ],
  revokeAccessToken: [
    { action: "plugin::strapi-plugin-oauth2.oauth-access-token.revoke", subject: null }
  ],
  generateClientKeyPair: [
    { action: "plugin::strapi-plugin-oauth2.oauth-client.generate-keypair", subject: null }
  ]
};
const HomePage = () => {
  const { formatDate } = reactIntl.useIntl();
  const { get, post, put, del } = admin.useFetchClient();
  const { toggleNotification } = admin.useNotification();
  const navigate = reactRouterDom.useNavigate();
  const [globalSettings, setGlobalSettings] = react.useState();
  const [globalLoading, setGlobalLoading] = react.useState(false);
  const [editGlobalSettings, setEditGlobalSettings] = react.useState();
  const [isEditGlobalSettingsModalOpen, setIsEditGlobalSettingsModalOpen] = react.useState(false);
  const [clients, setClients] = react.useState([]);
  const [loading, setLoading] = react.useState(true);
  const [pagination, setPagination] = react.useState({
    page: 1,
    pageSize: 10,
    pageCount: 1,
    total: 0
  });
  const [isCreateModalOpen, setIsCreateModalOpen] = react.useState(false);
  const [isEditModalOpen, setIsEditModalOpen] = react.useState(false);
  const [isSecretModalOpen, setIsSecretModalOpen] = react.useState(false);
  const [editingClient, setEditingClient] = react.useState(null);
  const [newClient, setNewClient] = react.useState({
    name: "",
    scopes: [],
    clientType: "CONFIDENTIAL",
    redirectUris: [""],
    meta: "",
    userDocumentId: null
  });
  const [createdSecret, setCreatedSecret] = react.useState(null);
  const [showSecret, setShowSecret] = react.useState(false);
  const [availableScopes, setAvailableScopes] = react.useState({});
  const [users, setUsers] = react.useState([]);
  const [userSearchQuery, setUserSearchQuery] = react.useState("");
  const [isLoadingUsers, setIsLoadingUsers] = react.useState(false);
  const [expandedSections, setExpandedSections] = react.useState({});
  const [editExpandedSections, setEditExpandedSections] = react.useState({});
  const [globalExpandedSections, setGlobalExpandedSections] = react.useState({});
  const fetchGlobalSettings = async () => {
    try {
      setGlobalLoading(true);
      const response = await get("/strapi-plugin-oauth2/global-settings");
      const { data } = response.data;
      setGlobalSettings(data);
    } catch (error) {
      toggleNotification({
        type: "danger",
        message: "Failed to fetch global settings"
      });
    } finally {
      setGlobalLoading(false);
    }
  };
  const fetchClients = async (page = pagination.page, pageSize = pagination.pageSize) => {
    try {
      setLoading(true);
      const params = qs__default.default.stringify(
        {
          populate: ["user"],
          sort: ["createdAt:desc"],
          pagination: {
            page,
            pageSize
          }
        },
        { encodeValuesOnly: true }
      );
      const response = await get(`/strapi-plugin-oauth2/clients?${params}`);
      const { data, meta } = response.data;
      setClients(data || []);
      if (meta?.pagination) {
        setPagination(meta.pagination);
      }
    } catch (error) {
      toggleNotification({
        type: "danger",
        message: "Failed to fetch OAuth clients"
      });
    } finally {
      setLoading(false);
    }
  };
  const fetchAvailableScopes = async () => {
    try {
      const { data } = await get("/strapi-plugin-oauth2/scopes");
      setAvailableScopes(data || {});
    } catch (error) {
      toggleNotification({
        type: "danger",
        message: "Failed to fetch available scopes"
      });
    }
  };
  const searchUsers = async (query) => {
    if (!query || query.length < 2) {
      setUsers([]);
      return;
    }
    try {
      setIsLoadingUsers(true);
      const params = new URLSearchParams({
        filters: JSON.stringify({
          $or: [{ username: { $contains: query } }, { email: { $contains: query } }]
        }),
        sort: "username:asc",
        pagination: JSON.stringify({ pageSize: 10 })
      });
      const { data } = await get(
        `/content-manager/collection-types/plugin::users-permissions.user?${params.toString()}`
      );
      setUsers(data?.results || []);
    } catch (error) {
      toggleNotification({
        type: "danger",
        message: "Failed to search users"
      });
      setUsers([]);
    } finally {
      setIsLoadingUsers(false);
    }
  };
  react.useEffect(() => {
    fetchClients();
    fetchAvailableScopes();
    fetchGlobalSettings();
  }, []);
  react.useEffect(() => {
    const timer = setTimeout(() => {
      searchUsers(userSearchQuery);
    }, 500);
    return () => clearTimeout(timer);
  }, [userSearchQuery]);
  react.useEffect(() => {
    if (isCreateModalOpen) {
      setNewClient({
        name: "",
        scopes: [],
        clientType: "CONFIDENTIAL",
        redirectUris: [""],
        meta: "",
        userDocumentId: null
      });
    }
  }, [isCreateModalOpen]);
  const handleUpdateGlobalSettings = async () => {
    if (!editGlobalSettings) return;
    try {
      await put(`/strapi-plugin-oauth2/global-settings/${editGlobalSettings.documentId}`, {
        data: {
          scopes: editGlobalSettings.scopes
        }
      });
      setIsEditGlobalSettingsModalOpen(false);
      setEditGlobalSettings(void 0);
      fetchGlobalSettings();
      toggleNotification({
        type: "success",
        message: "Global settings updated successfully"
      });
    } catch (error) {
      toggleNotification({
        type: "danger",
        message: "Failed to update Global settings"
      });
    }
  };
  const handleCreateClient = async () => {
    try {
      const meta = newClient.meta ? JSON.parse(newClient.meta) : {};
      const redirectUris = newClient.redirectUris.filter((uri) => uri.trim() !== "");
      const response = await post("/strapi-plugin-oauth2/clients", {
        data: {
          name: newClient.name,
          scopes: newClient.scopes,
          redirectUris,
          meta,
          user: newClient.userDocumentId,
          clientType: newClient.clientType
        }
      });
      const { data } = response.data;
      setCreatedSecret(data);
      setIsCreateModalOpen(false);
      setIsSecretModalOpen(true);
      setNewClient({
        name: "",
        scopes: [],
        clientType: "CONFIDENTIAL",
        redirectUris: [""],
        meta: "",
        userDocumentId: null
      });
      fetchClients(1, pagination.pageSize);
      toggleNotification({
        type: "success",
        message: "OAuth client created successfully"
      });
    } catch (error) {
      toggleNotification({
        type: "danger",
        message: "Failed to create OAuth client"
      });
    }
  };
  const handleDeleteClient = async (documentId) => {
    if (!confirm("Are you sure you want to delete this client?")) return;
    try {
      await del(`/strapi-plugin-oauth2/clients/${documentId}`);
      fetchClients(pagination.page, pagination.pageSize);
      toggleNotification({
        type: "success",
        message: "OAuth client deleted successfully"
      });
    } catch (error) {
      toggleNotification({
        type: "danger",
        message: "Failed to delete OAuth client"
      });
    }
  };
  const handleEditClient = (client) => {
    console.log("Editing client:", client);
    setEditingClient(client);
    setIsEditModalOpen(true);
  };
  const handleUpdateClient = async () => {
    if (!editingClient) return;
    try {
      const redirectUris = (editingClient.redirectUris || []).filter((uri) => uri.trim() !== "");
      await put(`/strapi-plugin-oauth2/clients/${editingClient.documentId}`, {
        data: {
          name: editingClient.name,
          scopes: editingClient.scopes,
          redirectUris
        }
      });
      setIsEditModalOpen(false);
      setEditingClient(null);
      fetchClients(pagination.page, pagination.pageSize);
      toggleNotification({
        type: "success",
        message: "OAuth client updated successfully"
      });
    } catch (error) {
      toggleNotification({
        type: "danger",
        message: "Failed to update OAuth client"
      });
    }
  };
  const handleRotateSecret = async (documentId) => {
    if (!confirm("Are you sure you want to rotate the secret? The old secret will be invalidated."))
      return;
    try {
      const response = await put(`/strapi-plugin-oauth2/clients-rotate/${documentId}`);
      const { data } = response.data;
      setCreatedSecret(data);
      setIsSecretModalOpen(true);
      toggleNotification({
        type: "success",
        message: "Client secret rotated successfully"
      });
    } catch (error) {
      toggleNotification({
        type: "danger",
        message: "Failed to rotate client secret"
      });
    }
  };
  const handleRotateKeypair = async (documentId) => {
    if (!confirm(
      "Are you sure you want to regenerate the RSA keypair? The old keys will be invalidated."
    ))
      return;
    try {
      const response = await put(`/strapi-plugin-oauth2/clients-keypair/${documentId}`);
      const { data } = response.data;
      setCreatedSecret(data);
      setIsSecretModalOpen(true);
      toggleNotification({
        type: "success",
        message: "RSA keypair regenerated successfully"
      });
    } catch (error) {
      toggleNotification({
        type: "danger",
        message: "Failed to regenerate RSA keypair"
      });
    }
  };
  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text);
    toggleNotification({
      type: "success",
      message: "Copied to clipboard"
    });
  };
  const handleScopeToggle = (scopeName) => {
    setNewClient((prev) => ({
      ...prev,
      scopes: prev.scopes.includes(scopeName) ? prev.scopes.filter((s) => s !== scopeName) : [...prev.scopes, scopeName]
    }));
  };
  const handleSectionToggle = (sectionScopes) => {
    const scopeNames = sectionScopes.map((s) => s.name);
    const allSelected = scopeNames.every((scopeName) => newClient.scopes.includes(scopeName));
    setNewClient((prev) => ({
      ...prev,
      scopes: allSelected ? prev.scopes.filter((s) => !scopeNames.includes(s)) : [.../* @__PURE__ */ new Set([...prev.scopes, ...scopeNames])]
    }));
  };
  const handleAddRedirectUri = () => {
    setNewClient((prev) => ({
      ...prev,
      redirectUris: [...prev.redirectUris, ""]
    }));
  };
  const handleRemoveRedirectUri = (index) => {
    setNewClient((prev) => ({
      ...prev,
      redirectUris: prev.redirectUris.filter((_2, i) => i !== index)
    }));
  };
  const handleRedirectUriChange = (index, value) => {
    setNewClient((prev) => ({
      ...prev,
      redirectUris: prev.redirectUris.map((uri, i) => i === index ? value : uri)
    }));
  };
  const handleEditAddRedirectUri = () => {
    if (!editingClient) return;
    setEditingClient({
      ...editingClient,
      redirectUris: [...editingClient.redirectUris || [], ""]
    });
  };
  const handleEditRemoveRedirectUri = (index) => {
    if (!editingClient) return;
    setEditingClient({
      ...editingClient,
      redirectUris: (editingClient.redirectUris || []).filter((_2, i) => i !== index)
    });
  };
  const handleEditRedirectUriChange = (index, value) => {
    if (!editingClient) return;
    setEditingClient({
      ...editingClient,
      redirectUris: (editingClient.redirectUris || []).map((uri, i) => i === index ? value : uri)
    });
  };
  const handleEditScopeToggle = (scopeName) => {
    if (!editingClient) return;
    setEditingClient({
      ...editingClient,
      scopes: editingClient.scopes.includes(scopeName) ? editingClient.scopes.filter((s) => s !== scopeName) : [...editingClient.scopes, scopeName]
    });
  };
  const handleEditSectionToggle = (sectionScopes) => {
    if (!editingClient) return;
    const scopeNames = sectionScopes.map((s) => s.name);
    const allSelected = scopeNames.every((scopeName) => editingClient.scopes.includes(scopeName));
    setEditingClient({
      ...editingClient,
      scopes: allSelected ? editingClient.scopes.filter((s) => !scopeNames.includes(s)) : [.../* @__PURE__ */ new Set([...editingClient.scopes, ...scopeNames])]
    });
  };
  const toggleSectionExpand = (section) => {
    setExpandedSections((prev) => ({
      ...prev,
      [section]: !prev[section]
    }));
  };
  const toggleEditSectionExpand = (section) => {
    setEditExpandedSections((prev) => ({
      ...prev,
      [section]: !prev[section]
    }));
  };
  const toggleGlobalSectionExpand = (section) => {
    setGlobalExpandedSections((prev) => ({
      ...prev,
      [section]: !prev[section]
    }));
  };
  const handlePageChange = (page) => {
    fetchClients(page, pagination.pageSize);
  };
  const handlePageSizeChange = (pageSize) => {
    fetchClients(1, parseInt(pageSize));
  };
  const handleGlobalScopeToggle = (scopeName) => {
    if (!editGlobalSettings) return;
    setEditGlobalSettings({
      ...editGlobalSettings,
      scopes: editGlobalSettings.scopes.includes(scopeName) ? editGlobalSettings.scopes.filter((s) => s !== scopeName) : [...editGlobalSettings.scopes, scopeName]
    });
  };
  const handleGlobalSectionToggle = (sectionScopes) => {
    if (!editGlobalSettings) return;
    const scopeNames = sectionScopes.map((s) => s.name);
    const allSelected = scopeNames.every(
      (scopeName) => editGlobalSettings.scopes.includes(scopeName)
    );
    setEditGlobalSettings({
      ...editGlobalSettings,
      scopes: allSelected ? editGlobalSettings.scopes.filter((s) => !scopeNames.includes(s)) : [.../* @__PURE__ */ new Set([...editGlobalSettings.scopes, ...scopeNames])]
    });
  };
  const getPaginationPages = () => {
    const MAX_PAGES = 5;
    const { page: activePage, pageCount } = pagination;
    const pages = [];
    if (pageCount <= MAX_PAGES) {
      for (let i = 1; i <= pageCount; i++) {
        pages.push(i);
      }
    } else {
      if (activePage <= 3) {
        pages.push(1, 2, 3, 4, -1, pageCount);
      } else if (activePage >= pageCount - 2) {
        pages.push(1, -1, pageCount - 3, pageCount - 2, pageCount - 1, pageCount);
      } else {
        pages.push(1, -1, activePage - 1, activePage, activePage + 1, -2, pageCount);
      }
    }
    return pages;
  };
  return /* @__PURE__ */ jsxRuntime.jsxs(admin.Layouts.Root, { children: [
    /* @__PURE__ */ jsxRuntime.jsx(admin.Page.Title, { children: "OAuth2 Clients" }),
    /* @__PURE__ */ jsxRuntime.jsxs(admin.Page.Main, { children: [
      /* @__PURE__ */ jsxRuntime.jsx(admin.Layouts.Header, { title: "OAuth2 Clients", subtitle: `${pagination.total} client(s) found` }),
      /* @__PURE__ */ jsxRuntime.jsxs(admin.Layouts.Content, { children: [
        /* @__PURE__ */ jsxRuntime.jsxs(designSystem.Flex, { justifyContent: "space-between", marginBottom: 4, children: [
          /* @__PURE__ */ jsxRuntime.jsx(designSystem.Typography, { variant: "beta", children: "OAuth2 Global Scopes Settings" }),
          /* @__PURE__ */ jsxRuntime.jsx(
            designSystem.Button,
            {
              startIcon: /* @__PURE__ */ jsxRuntime.jsx(icons.Pencil, {}),
              onClick: () => {
                setEditGlobalSettings(globalSettings);
                setIsEditGlobalSettingsModalOpen(true);
              },
              children: "Edit"
            }
          )
        ] }),
        globalLoading ? /* @__PURE__ */ jsxRuntime.jsx(designSystem.Typography, { children: "Loading..." }) : (globalSettings?.scopes?.length || 0) > 0 ? /* @__PURE__ */ jsxRuntime.jsx(designSystem.Box, { padding: 4, background: "neutral0", hasRadius: true, marginBottom: 6, children: /* @__PURE__ */ jsxRuntime.jsx(designSystem.Flex, { direction: "row", gap: 3, wrap: "wrap", alignItems: "flex-start", children: Object.entries(availableScopes).map(([section, scopes]) => {
          const selectedScopesInSection = scopes.filter(
            (scope) => (globalSettings?.scopes || []).includes(scope.name)
          );
          if (selectedScopesInSection.length === 0) return null;
          return /* @__PURE__ */ jsxRuntime.jsx(designSystem.Box, { width: "48%", minWidth: "250px", children: /* @__PURE__ */ jsxRuntime.jsxs(designSystem.Flex, { direction: "column", gap: 2, alignItems: "flex-start", children: [
            /* @__PURE__ */ jsxRuntime.jsxs(designSystem.Typography, { fontWeight: "bold", variant: "omega", children: [
              section,
              " (",
              selectedScopesInSection.length,
              ")"
            ] }),
            /* @__PURE__ */ jsxRuntime.jsx(designSystem.Box, { paddingLeft: 6, children: /* @__PURE__ */ jsxRuntime.jsx(designSystem.Flex, { direction: "column", gap: 2, alignItems: "flex-start", children: selectedScopesInSection.map((scope) => /* @__PURE__ */ jsxRuntime.jsxs(designSystem.Flex, { gap: 2, alignItems: "center", children: [
              /* @__PURE__ */ jsxRuntime.jsx(
                designSystem.Box,
                {
                  paddingLeft: 2,
                  paddingRight: 2,
                  paddingTop: 1,
                  paddingBottom: 1,
                  background: scope.action.includes("find") || scope.action.includes("get") || scope.action.includes("list") ? "success500" : scope.action.includes("update") ? "warning500" : scope.action.includes("delete") || scope.action.includes("remove") || scope.action.includes("destroy") ? "danger500" : "primary500",
                  hasRadius: true,
                  children: /* @__PURE__ */ jsxRuntime.jsx(designSystem.Typography, { variant: "pi", fontWeight: "bold", fontSize: 1, children: scope.action })
                }
              ),
              /* @__PURE__ */ jsxRuntime.jsx(designSystem.Typography, { variant: "pi", fontFamily: "monospace", children: scope.name })
            ] }, scope.name)) }) })
          ] }) }, section);
        }) }) }) : /* @__PURE__ */ jsxRuntime.jsx(designSystem.Box, { padding: 4, background: "neutral0", hasRadius: true, marginBottom: 6, children: /* @__PURE__ */ jsxRuntime.jsx(designSystem.Typography, { children: "No global scopes configured." }) }),
        /* @__PURE__ */ jsxRuntime.jsxs(designSystem.Flex, { justifyContent: "space-between", marginBottom: 4, children: [
          /* @__PURE__ */ jsxRuntime.jsxs(designSystem.Flex, { direction: "column", gap: 1, alignItems: "flex-start", children: [
            /* @__PURE__ */ jsxRuntime.jsx(designSystem.Typography, { variant: "beta", children: "OAuth2 Clients" }),
            pagination.total > 0 && /* @__PURE__ */ jsxRuntime.jsxs(designSystem.Typography, { variant: "pi", textColor: "neutral600", children: [
              pagination.total,
              " client(s) found"
            ] })
          ] }),
          /* @__PURE__ */ jsxRuntime.jsxs(designSystem.Flex, { gap: 2, children: [
            /* @__PURE__ */ jsxRuntime.jsx(
              designSystem.Button,
              {
                variant: "secondary",
                startIcon: /* @__PURE__ */ jsxRuntime.jsx(icons.Key, {}),
                onClick: () => navigate("access-tokens"),
                persmission: pluginPermissions.readAccessTokens,
                children: "View All Access Tokens"
              }
            ),
            /* @__PURE__ */ jsxRuntime.jsx(designSystem.Button, { startIcon: /* @__PURE__ */ jsxRuntime.jsx(icons.Plus, {}), onClick: () => setIsCreateModalOpen(true), children: "Create Client" })
          ] })
        ] }),
        loading ? /* @__PURE__ */ jsxRuntime.jsx(designSystem.Typography, { children: "Loading..." }) : /* @__PURE__ */ jsxRuntime.jsxs(designSystem.Table, { children: [
          /* @__PURE__ */ jsxRuntime.jsx(designSystem.Thead, { children: /* @__PURE__ */ jsxRuntime.jsxs(designSystem.Tr, { children: [
            /* @__PURE__ */ jsxRuntime.jsx(designSystem.Th, { children: /* @__PURE__ */ jsxRuntime.jsx(designSystem.Typography, { variant: "sigma", children: "Name" }) }),
            /* @__PURE__ */ jsxRuntime.jsx(designSystem.Th, { children: /* @__PURE__ */ jsxRuntime.jsx(designSystem.Typography, { variant: "sigma", children: "User ID" }) }),
            /* @__PURE__ */ jsxRuntime.jsx(designSystem.Th, { children: /* @__PURE__ */ jsxRuntime.jsx(designSystem.Typography, { variant: "sigma", children: "Client ID" }) }),
            /* @__PURE__ */ jsxRuntime.jsx(designSystem.Th, { children: /* @__PURE__ */ jsxRuntime.jsx(designSystem.Typography, { variant: "sigma", children: "Scopes" }) }),
            /* @__PURE__ */ jsxRuntime.jsx(designSystem.Th, { children: /* @__PURE__ */ jsxRuntime.jsx(designSystem.Typography, { variant: "sigma", children: "Client Type" }) }),
            /* @__PURE__ */ jsxRuntime.jsx(designSystem.Th, { children: /* @__PURE__ */ jsxRuntime.jsx(designSystem.Typography, { variant: "sigma", children: "Created By" }) }),
            /* @__PURE__ */ jsxRuntime.jsx(designSystem.Th, { children: /* @__PURE__ */ jsxRuntime.jsx(designSystem.Typography, { variant: "sigma", children: "Status" }) }),
            /* @__PURE__ */ jsxRuntime.jsx(designSystem.Th, { children: /* @__PURE__ */ jsxRuntime.jsx(designSystem.Typography, { variant: "sigma", children: "Updated" }) }),
            /* @__PURE__ */ jsxRuntime.jsx(designSystem.Th, { children: /* @__PURE__ */ jsxRuntime.jsx(designSystem.Typography, { variant: "sigma", children: "Created" }) }),
            /* @__PURE__ */ jsxRuntime.jsx(designSystem.Th, { children: /* @__PURE__ */ jsxRuntime.jsx(designSystem.Typography, { variant: "sigma", children: "Actions" }) })
          ] }) }),
          /* @__PURE__ */ jsxRuntime.jsx(designSystem.Tbody, { children: clients.map((client) => /* @__PURE__ */ jsxRuntime.jsxs(designSystem.Tr, { children: [
            /* @__PURE__ */ jsxRuntime.jsx(
              designSystem.Td,
              {
                style: {
                  verticalAlign: "top"
                },
                children: /* @__PURE__ */ jsxRuntime.jsx(designSystem.Box, { style: { marginTop: "21px" }, children: /* @__PURE__ */ jsxRuntime.jsx(designSystem.Typography, { children: client.name }) })
              }
            ),
            /* @__PURE__ */ jsxRuntime.jsx(
              designSystem.Td,
              {
                style: {
                  verticalAlign: client.createdType === "BACK_OFFICE" ? "top" : "center"
                },
                children: /* @__PURE__ */ jsxRuntime.jsxs(designSystem.Flex, { gap: 2, alignItems: "center", children: [
                  /* @__PURE__ */ jsxRuntime.jsx(designSystem.Typography, { fontFamily: "monospace", children: client.user.documentId }),
                  /* @__PURE__ */ jsxRuntime.jsx(
                    designSystem.IconButton,
                    {
                      onClick: () => copyToClipboard(client.user.documentId),
                      label: "Copy",
                      size: "S",
                      withTooltip: false,
                      children: /* @__PURE__ */ jsxRuntime.jsx(icons.Duplicate, {})
                    }
                  )
                ] })
              }
            ),
            /* @__PURE__ */ jsxRuntime.jsx(
              designSystem.Td,
              {
                style: {
                  verticalAlign: client.createdType === "BACK_OFFICE" ? "top" : "center"
                },
                children: /* @__PURE__ */ jsxRuntime.jsxs(designSystem.Flex, { gap: 2, alignItems: "center", children: [
                  /* @__PURE__ */ jsxRuntime.jsx(designSystem.Typography, { fontFamily: "monospace", children: client.clientId }),
                  /* @__PURE__ */ jsxRuntime.jsx(
                    designSystem.IconButton,
                    {
                      onClick: () => copyToClipboard(client.clientId),
                      label: "Copy",
                      size: "S",
                      withTooltip: false,
                      children: /* @__PURE__ */ jsxRuntime.jsx(icons.Duplicate, {})
                    }
                  )
                ] })
              }
            ),
            /* @__PURE__ */ jsxRuntime.jsx(
              designSystem.Td,
              {
                style: {
                  verticalAlign: client.createdType === "BACK_OFFICE" ? "top" : "center"
                },
                children: client.createdType === "BACK_OFFICE" ? (client.scopes || []).map((scope, index) => /* @__PURE__ */ jsxRuntime.jsx(designSystem.Box, { children: /* @__PURE__ */ jsxRuntime.jsx(designSystem.Typography, { children: scope }) }, index)) : /* @__PURE__ */ jsxRuntime.jsx(designSystem.Typography, { style: { fontSize: "100%" }, children: "Follow by Global Scopes Settings" })
              }
            ),
            /* @__PURE__ */ jsxRuntime.jsx(
              designSystem.Td,
              {
                style: {
                  verticalAlign: client.createdType === "BACK_OFFICE" ? "top" : "center"
                },
                children: /* @__PURE__ */ jsxRuntime.jsx(designSystem.Typography, { children: ___default.default.capitalize(client.clientType.toLowerCase()) })
              }
            ),
            /* @__PURE__ */ jsxRuntime.jsx(
              designSystem.Td,
              {
                style: {
                  verticalAlign: client.createdType === "BACK_OFFICE" ? "top" : "center"
                },
                children: /* @__PURE__ */ jsxRuntime.jsx(designSystem.Typography, { children: ___default.default.capitalize(client.createdType.toLowerCase()) })
              }
            ),
            /* @__PURE__ */ jsxRuntime.jsx(
              designSystem.Td,
              {
                style: {
                  verticalAlign: client.createdType === "BACK_OFFICE" ? "top" : "center"
                },
                children: client.active ? /* @__PURE__ */ jsxRuntime.jsx(designSystem.Badge, { active: true, children: "Active" }) : /* @__PURE__ */ jsxRuntime.jsx(designSystem.Badge, { children: "Inactive" })
              }
            ),
            /* @__PURE__ */ jsxRuntime.jsx(
              designSystem.Td,
              {
                style: {
                  verticalAlign: client.createdType === "BACK_OFFICE" ? "top" : "center"
                },
                children: /* @__PURE__ */ jsxRuntime.jsx(designSystem.Typography, { children: formatDate(client.updatedAt, {
                  year: "numeric",
                  month: "short",
                  day: "2-digit",
                  hour: "2-digit",
                  minute: "2-digit"
                }) })
              }
            ),
            /* @__PURE__ */ jsxRuntime.jsx(
              designSystem.Td,
              {
                style: {
                  verticalAlign: client.createdType === "BACK_OFFICE" ? "top" : "center"
                },
                children: /* @__PURE__ */ jsxRuntime.jsx(designSystem.Typography, { children: formatDate(client.createdAt, {
                  year: "numeric",
                  month: "short",
                  day: "2-digit",
                  hour: "2-digit",
                  minute: "2-digit"
                }) })
              }
            ),
            /* @__PURE__ */ jsxRuntime.jsx(
              designSystem.Td,
              {
                style: {
                  verticalAlign: client.createdType === "BACK_OFFICE" ? "top" : "center"
                },
                children: /* @__PURE__ */ jsxRuntime.jsxs(designSystem.Flex, { gap: 1, children: [
                  /* @__PURE__ */ jsxRuntime.jsx(
                    designSystem.IconButton,
                    {
                      label: "View Access Tokens",
                      onClick: () => navigate(`access-tokens/${client.documentId}`),
                      variant: "tertiary",
                      persmission: pluginPermissions.readAccessTokens,
                      withTooltip: false,
                      children: /* @__PURE__ */ jsxRuntime.jsx(icons.Key, {})
                    }
                  ),
                  /* @__PURE__ */ jsxRuntime.jsx(
                    designSystem.IconButton,
                    {
                      label: "Edit",
                      onClick: () => handleEditClient(client),
                      variant: "tertiary",
                      permission: pluginPermissions.updateGlobalSettings,
                      withTooltip: false,
                      children: /* @__PURE__ */ jsxRuntime.jsx(icons.Pencil, {})
                    }
                  ),
                  /* @__PURE__ */ jsxRuntime.jsx(
                    designSystem.IconButton,
                    {
                      label: "Regenerate Secret",
                      onClick: () => handleRotateSecret(client.documentId),
                      variant: "secondary",
                      permission: pluginPermissions.rotateClient,
                      withTooltip: false,
                      children: /* @__PURE__ */ jsxRuntime.jsx(icons.ArrowClockwise, {})
                    }
                  ),
                  /* @__PURE__ */ jsxRuntime.jsx(
                    designSystem.IconButton,
                    {
                      label: "Regenerate RSA Keypair",
                      onClick: () => handleRotateKeypair(client.documentId),
                      variant: "secondary",
                      permission: pluginPermissions.generateClientKeyPair,
                      withTooltip: false,
                      children: /* @__PURE__ */ jsxRuntime.jsx(icons.Key, {})
                    }
                  ),
                  /* @__PURE__ */ jsxRuntime.jsx(
                    designSystem.IconButton,
                    {
                      label: "Delete",
                      onClick: () => handleDeleteClient(client.documentId),
                      variant: "danger-light",
                      permission: pluginPermissions.deleteClient,
                      withTooltip: false,
                      children: /* @__PURE__ */ jsxRuntime.jsx(icons.Trash, {})
                    }
                  )
                ] })
              }
            )
          ] }, client.documentId)) })
        ] }),
        !loading && /* @__PURE__ */ jsxRuntime.jsx(designSystem.Box, { marginTop: 4, children: /* @__PURE__ */ jsxRuntime.jsxs(designSystem.Flex, { justifyContent: "space-between", alignItems: "center", children: [
          /* @__PURE__ */ jsxRuntime.jsxs(
            designSystem.SingleSelect,
            {
              size: "S",
              value: pagination.pageSize.toString(),
              onChange: handlePageSizeChange,
              placeholder: "Page size",
              children: [
                /* @__PURE__ */ jsxRuntime.jsx(designSystem.SingleSelectOption, { value: "10", children: "10 per page" }),
                /* @__PURE__ */ jsxRuntime.jsx(designSystem.SingleSelectOption, { value: "25", children: "25 per page" }),
                /* @__PURE__ */ jsxRuntime.jsx(designSystem.SingleSelectOption, { value: "50", children: "50 per page" }),
                /* @__PURE__ */ jsxRuntime.jsx(designSystem.SingleSelectOption, { value: "100", children: "100 per page" })
              ]
            }
          ),
          /* @__PURE__ */ jsxRuntime.jsxs(
            designSystem.Pagination,
            {
              activePage: pagination.page,
              pageCount: pagination.pageCount,
              onPageChange: handlePageChange,
              children: [
                /* @__PURE__ */ jsxRuntime.jsx(
                  designSystem.PreviousLink,
                  {
                    onClick: () => pagination.page > 1 && handlePageChange(pagination.page - 1),
                    children: "Go to previous page"
                  }
                ),
                getPaginationPages().map((pageNum, index) => {
                  if (pageNum === -1 || pageNum === -2) {
                    return /* @__PURE__ */ jsxRuntime.jsx(designSystem.Dots, { children: "..." }, `dots-${index}`);
                  }
                  return /* @__PURE__ */ jsxRuntime.jsxs(
                    designSystem.PageLink,
                    {
                      number: pageNum,
                      onClick: () => handlePageChange(pageNum),
                      children: [
                        "Go to page ",
                        pageNum
                      ]
                    },
                    pageNum
                  );
                }),
                /* @__PURE__ */ jsxRuntime.jsx(
                  designSystem.NextLink,
                  {
                    onClick: () => pagination.page < pagination.pageCount && handlePageChange(pagination.page + 1),
                    children: "Go to next page"
                  }
                )
              ]
            }
          )
        ] }) }),
        /* @__PURE__ */ jsxRuntime.jsx(
          designSystem.Modal.Root,
          {
            open: isEditGlobalSettingsModalOpen,
            onOpenChange: setIsEditGlobalSettingsModalOpen,
            children: /* @__PURE__ */ jsxRuntime.jsxs(designSystem.Modal.Content, { children: [
              /* @__PURE__ */ jsxRuntime.jsx(designSystem.Modal.Header, { children: /* @__PURE__ */ jsxRuntime.jsx(designSystem.Modal.Title, { children: "Edit Global OAuth Scopes" }) }),
              /* @__PURE__ */ jsxRuntime.jsx(designSystem.Modal.Body, { children: editGlobalSettings && /* @__PURE__ */ jsxRuntime.jsx(designSystem.Flex, { direction: "column", gap: 4, width: "100%", children: /* @__PURE__ */ jsxRuntime.jsxs(designSystem.Field.Root, { required: true, width: "100%", children: [
                /* @__PURE__ */ jsxRuntime.jsxs(designSystem.Flex, { justifyContent: "space-between", alignItems: "center", marginBottom: 2, children: [
                  /* @__PURE__ */ jsxRuntime.jsx(designSystem.Field.Label, { children: "Scopes" }),
                  /* @__PURE__ */ jsxRuntime.jsxs(designSystem.Flex, { gap: 2, children: [
                    /* @__PURE__ */ jsxRuntime.jsx(
                      designSystem.Button,
                      {
                        variant: "tertiary",
                        size: "S",
                        onClick: () => {
                          const allScopeNames = Object.values(availableScopes).flat().map((s) => s.name);
                          setEditGlobalSettings({
                            ...editGlobalSettings,
                            scopes: allScopeNames
                          });
                        },
                        children: "Select All"
                      }
                    ),
                    /* @__PURE__ */ jsxRuntime.jsx(
                      designSystem.Button,
                      {
                        variant: "tertiary",
                        size: "S",
                        onClick: () => setEditGlobalSettings({ ...editGlobalSettings, scopes: [] }),
                        children: "Deselect All"
                      }
                    )
                  ] })
                ] }),
                /* @__PURE__ */ jsxRuntime.jsx(
                  designSystem.Box,
                  {
                    maxHeight: "300px",
                    width: "100%",
                    overflow: "auto",
                    padding: 3,
                    background: "neutral100",
                    hasRadius: true,
                    children: /* @__PURE__ */ jsxRuntime.jsx(designSystem.Flex, { direction: "row", gap: 3, wrap: "wrap", alignItems: "flex-start", children: Object.entries(availableScopes).map(([section, scopes]) => {
                      const scopeNames = scopes.map((s) => s.name);
                      const allSelected = scopeNames.every(
                        (scopeName) => editGlobalSettings.scopes.includes(scopeName)
                      );
                      const isExpanded = globalExpandedSections[section];
                      return /* @__PURE__ */ jsxRuntime.jsx(designSystem.Box, { width: "48%", minWidth: "250px", children: /* @__PURE__ */ jsxRuntime.jsxs(designSystem.Flex, { direction: "column", gap: 2, alignItems: "flex-start", children: [
                        /* @__PURE__ */ jsxRuntime.jsxs(designSystem.Flex, { gap: 2, alignItems: "center", width: "100%", children: [
                          /* @__PURE__ */ jsxRuntime.jsx(
                            designSystem.Checkbox,
                            {
                              checked: allSelected,
                              onCheckedChange: () => handleGlobalSectionToggle(scopes),
                              children: /* @__PURE__ */ jsxRuntime.jsxs(designSystem.Typography, { fontWeight: "bold", variant: "omega", children: [
                                section,
                                " (",
                                scopes.length,
                                ")"
                              ] })
                            }
                          ),
                          /* @__PURE__ */ jsxRuntime.jsx(
                            designSystem.IconButton,
                            {
                              onClick: () => toggleGlobalSectionExpand(section),
                              label: isExpanded ? "Collapse" : "Expand",
                              variant: "ghost",
                              size: "S",
                              withTooltip: false,
                              children: isExpanded ? /* @__PURE__ */ jsxRuntime.jsx(icons.ChevronUp, {}) : /* @__PURE__ */ jsxRuntime.jsx(icons.ChevronDown, {})
                            }
                          )
                        ] }),
                        isExpanded && /* @__PURE__ */ jsxRuntime.jsx(designSystem.Box, { paddingLeft: 6, children: /* @__PURE__ */ jsxRuntime.jsx(designSystem.Flex, { direction: "column", gap: 2, alignItems: "flex-start", children: scopes.map((scope) => /* @__PURE__ */ jsxRuntime.jsx(
                          designSystem.Checkbox,
                          {
                            checked: editGlobalSettings.scopes.includes(scope.name),
                            onCheckedChange: () => handleGlobalScopeToggle(scope.name),
                            children: /* @__PURE__ */ jsxRuntime.jsxs(designSystem.Flex, { gap: 2, alignItems: "center", children: [
                              /* @__PURE__ */ jsxRuntime.jsx(
                                designSystem.Box,
                                {
                                  paddingLeft: 2,
                                  paddingRight: 2,
                                  paddingTop: 1,
                                  paddingBottom: 1,
                                  background: scope.action.includes("find") || scope.action.includes("get") || scope.action.includes("list") ? "success500" : scope.action.includes("update") ? "warning500" : scope.action.includes("delete") || scope.action.includes("remove") || scope.action.includes("destroy") ? "danger500" : "primary500",
                                  hasRadius: true,
                                  children: /* @__PURE__ */ jsxRuntime.jsx(
                                    designSystem.Typography,
                                    {
                                      variant: "pi",
                                      fontWeight: "bold",
                                      fontSize: 1,
                                      children: scope.action
                                    }
                                  )
                                }
                              ),
                              /* @__PURE__ */ jsxRuntime.jsx(designSystem.Typography, { variant: "pi", fontFamily: "monospace", children: scope.name })
                            ] })
                          },
                          scope.name
                        )) }) })
                      ] }) }, section);
                    }) })
                  }
                ),
                /* @__PURE__ */ jsxRuntime.jsxs(designSystem.Field.Hint, { children: [
                  "Selected: ",
                  editGlobalSettings.scopes.length,
                  " scope(s)"
                ] })
              ] }) }) }),
              /* @__PURE__ */ jsxRuntime.jsxs(designSystem.Modal.Footer, { children: [
                /* @__PURE__ */ jsxRuntime.jsx(designSystem.Modal.Close, { children: /* @__PURE__ */ jsxRuntime.jsx(designSystem.Button, { variant: "tertiary", children: "Cancel" }) }),
                /* @__PURE__ */ jsxRuntime.jsx(designSystem.Button, { onClick: handleUpdateGlobalSettings, disabled: !editGlobalSettings, children: "Update" })
              ] })
            ] })
          }
        ),
        /* @__PURE__ */ jsxRuntime.jsx(designSystem.Modal.Root, { open: isCreateModalOpen, onOpenChange: setIsCreateModalOpen, children: /* @__PURE__ */ jsxRuntime.jsxs(designSystem.Modal.Content, { children: [
          /* @__PURE__ */ jsxRuntime.jsx(designSystem.Modal.Header, { children: /* @__PURE__ */ jsxRuntime.jsx(designSystem.Modal.Title, { children: "Create OAuth Client" }) }),
          /* @__PURE__ */ jsxRuntime.jsx(designSystem.Modal.Body, { children: /* @__PURE__ */ jsxRuntime.jsxs(designSystem.Flex, { direction: "column", gap: 4, width: "100%", children: [
            /* @__PURE__ */ jsxRuntime.jsxs(designSystem.Field.Root, { required: true, width: "100%", children: [
              /* @__PURE__ */ jsxRuntime.jsx(designSystem.Field.Label, { children: "Name" }),
              /* @__PURE__ */ jsxRuntime.jsx(
                designSystem.Field.Input,
                {
                  value: newClient.name,
                  onChange: (e) => setNewClient({ ...newClient, name: e.target.value }),
                  placeholder: "My Application"
                }
              )
            ] }),
            /* @__PURE__ */ jsxRuntime.jsxs(designSystem.Field.Root, { required: true, width: "100%", children: [
              /* @__PURE__ */ jsxRuntime.jsx(designSystem.Field.Label, { children: "User" }),
              /* @__PURE__ */ jsxRuntime.jsx(
                designSystem.Combobox,
                {
                  value: newClient.userDocumentId,
                  onChange: (value) => setNewClient({ ...newClient, userDocumentId: value }),
                  onInputChange: (e) => setUserSearchQuery(e.target.value),
                  placeholder: "Type to search users...",
                  loading: isLoadingUsers,
                  children: users.length === 0 && userSearchQuery.length >= 2 && !isLoadingUsers ? /* @__PURE__ */ jsxRuntime.jsx(designSystem.ComboboxOption, { value: "", disabled: true, children: "No users found" }) : users.map((user) => /* @__PURE__ */ jsxRuntime.jsxs(designSystem.ComboboxOption, { value: user.documentId, children: [
                    user.username,
                    " (",
                    user.email,
                    ")"
                  ] }, user.documentId))
                }
              ),
              userSearchQuery.length > 0 && userSearchQuery.length < 2 && /* @__PURE__ */ jsxRuntime.jsx(designSystem.Field.Hint, { children: "Type at least 2 characters to search" })
            ] }),
            /* @__PURE__ */ jsxRuntime.jsx(designSystem.Field.Root, { required: true, width: "100%", children: /* @__PURE__ */ jsxRuntime.jsxs(
              designSystem.Radio.Group,
              {
                defaultValue: newClient.clientType,
                "aria-label": "Theme",
                onValueChange: (value) => setNewClient({ ...newClient, clientType: value }),
                children: [
                  /* @__PURE__ */ jsxRuntime.jsx(designSystem.Radio.Item, { value: "CONFIDENTIAL", children: "Confidential" }),
                  /* @__PURE__ */ jsxRuntime.jsx(designSystem.Radio.Item, { value: "PUBLIC", children: "Public" })
                ]
              }
            ) }),
            /* @__PURE__ */ jsxRuntime.jsxs(designSystem.Field.Root, { width: "100%", children: [
              /* @__PURE__ */ jsxRuntime.jsx(designSystem.Field.Label, { children: "Redirect URIs" }),
              /* @__PURE__ */ jsxRuntime.jsxs(designSystem.Flex, { direction: "column", gap: 2, alignItems: "flex-start", width: "100%", children: [
                (newClient.redirectUris || []).map((uri, index) => /* @__PURE__ */ jsxRuntime.jsxs(designSystem.Flex, { gap: 2, alignItems: "flex-end", width: "50%", children: [
                  /* @__PURE__ */ jsxRuntime.jsx(designSystem.Box, { flex: "1", children: /* @__PURE__ */ jsxRuntime.jsx(
                    designSystem.Field.Input,
                    {
                      value: uri,
                      onChange: (e) => handleRedirectUriChange(index, e.target.value),
                      placeholder: "https://example.com/callback"
                    }
                  ) }),
                  newClient.redirectUris?.length > 1 && /* @__PURE__ */ jsxRuntime.jsx(
                    designSystem.IconButton,
                    {
                      label: "Remove",
                      onClick: () => handleRemoveRedirectUri(index),
                      variant: "danger-light",
                      withTooltip: false,
                      children: /* @__PURE__ */ jsxRuntime.jsx(icons.Cross, {})
                    }
                  )
                ] }, index)),
                /* @__PURE__ */ jsxRuntime.jsx(
                  designSystem.Button,
                  {
                    variant: "secondary",
                    startIcon: /* @__PURE__ */ jsxRuntime.jsx(icons.Plus, {}),
                    onClick: handleAddRedirectUri,
                    size: "S",
                    children: "Add Redirect URI"
                  }
                )
              ] }),
              /* @__PURE__ */ jsxRuntime.jsx(designSystem.Field.Hint, { children: "Authorization callback URLs for OAuth flow" })
            ] }),
            /* @__PURE__ */ jsxRuntime.jsxs(designSystem.Field.Root, { required: true, width: "100%", children: [
              /* @__PURE__ */ jsxRuntime.jsxs(designSystem.Flex, { justifyContent: "space-between", alignItems: "center", marginBottom: 2, children: [
                /* @__PURE__ */ jsxRuntime.jsx(designSystem.Field.Label, { children: "Scopes" }),
                /* @__PURE__ */ jsxRuntime.jsxs(designSystem.Flex, { gap: 2, children: [
                  /* @__PURE__ */ jsxRuntime.jsx(
                    designSystem.Button,
                    {
                      variant: "tertiary",
                      size: "S",
                      onClick: () => {
                        const allScopeNames = Object.values(availableScopes).flat().map((s) => s.name);
                        setNewClient({ ...newClient, scopes: allScopeNames });
                      },
                      children: "Select All"
                    }
                  ),
                  /* @__PURE__ */ jsxRuntime.jsx(
                    designSystem.Button,
                    {
                      variant: "tertiary",
                      size: "S",
                      onClick: () => setNewClient({ ...newClient, scopes: [] }),
                      children: "Deselect All"
                    }
                  )
                ] })
              ] }),
              /* @__PURE__ */ jsxRuntime.jsx(
                designSystem.Box,
                {
                  maxHeight: "300px",
                  width: "100%",
                  overflow: "auto",
                  padding: 3,
                  background: "neutral100",
                  hasRadius: true,
                  children: /* @__PURE__ */ jsxRuntime.jsx(designSystem.Flex, { direction: "row", gap: 3, wrap: "wrap", alignItems: "flex-start", children: Object.entries(availableScopes).map(([section, scopes]) => {
                    const scopeNames = scopes.map((s) => s.name);
                    const allSelected = scopeNames.every(
                      (scopeName) => newClient.scopes.includes(scopeName)
                    );
                    const isExpanded = expandedSections[section];
                    return /* @__PURE__ */ jsxRuntime.jsx(designSystem.Box, { width: "48%", minWidth: "250px", children: /* @__PURE__ */ jsxRuntime.jsxs(designSystem.Flex, { direction: "column", gap: 2, alignItems: "flex-start", children: [
                      /* @__PURE__ */ jsxRuntime.jsxs(designSystem.Flex, { gap: 2, alignItems: "center", width: "100%", children: [
                        /* @__PURE__ */ jsxRuntime.jsx(
                          designSystem.Checkbox,
                          {
                            checked: allSelected,
                            onCheckedChange: () => handleSectionToggle(scopes),
                            children: /* @__PURE__ */ jsxRuntime.jsxs(designSystem.Typography, { fontWeight: "bold", variant: "omega", children: [
                              section,
                              " (",
                              scopes.length,
                              ")"
                            ] })
                          }
                        ),
                        /* @__PURE__ */ jsxRuntime.jsx(
                          designSystem.IconButton,
                          {
                            onClick: () => toggleSectionExpand(section),
                            label: isExpanded ? "Collapse" : "Expand",
                            variant: "ghost",
                            size: "S",
                            withTooltip: false,
                            children: isExpanded ? /* @__PURE__ */ jsxRuntime.jsx(icons.ChevronUp, {}) : /* @__PURE__ */ jsxRuntime.jsx(icons.ChevronDown, {})
                          }
                        )
                      ] }),
                      isExpanded && /* @__PURE__ */ jsxRuntime.jsx(designSystem.Box, { paddingLeft: 6, children: /* @__PURE__ */ jsxRuntime.jsx(designSystem.Flex, { direction: "column", gap: 2, alignItems: "flex-start", children: scopes.map((scope) => /* @__PURE__ */ jsxRuntime.jsx(
                        designSystem.Checkbox,
                        {
                          checked: newClient.scopes.includes(scope.name),
                          onCheckedChange: () => handleScopeToggle(scope.name),
                          children: /* @__PURE__ */ jsxRuntime.jsxs(designSystem.Flex, { gap: 2, alignItems: "center", children: [
                            /* @__PURE__ */ jsxRuntime.jsx(
                              designSystem.Box,
                              {
                                paddingLeft: 2,
                                paddingRight: 2,
                                paddingTop: 1,
                                paddingBottom: 1,
                                background: scope.action.includes("find") || scope.action.includes("get") || scope.action.includes("list") ? "success500" : scope.action.includes("update") ? "warning500" : scope.action.includes("delete") || scope.action.includes("remove") || scope.action.includes("destroy") ? "danger500" : "primary500",
                                hasRadius: true,
                                children: /* @__PURE__ */ jsxRuntime.jsx(
                                  designSystem.Typography,
                                  {
                                    variant: "pi",
                                    fontWeight: "bold",
                                    fontSize: 1,
                                    children: scope.action
                                  }
                                )
                              }
                            ),
                            /* @__PURE__ */ jsxRuntime.jsx(designSystem.Typography, { variant: "pi", fontFamily: "monospace", children: scope.name })
                          ] })
                        },
                        scope.name
                      )) }) })
                    ] }) }, section);
                  }) })
                }
              ),
              /* @__PURE__ */ jsxRuntime.jsxs(designSystem.Field.Hint, { children: [
                "Selected: ",
                newClient.scopes.length,
                " scope(s)"
              ] })
            ] })
          ] }) }),
          /* @__PURE__ */ jsxRuntime.jsxs(designSystem.Modal.Footer, { children: [
            /* @__PURE__ */ jsxRuntime.jsx(designSystem.Modal.Close, { children: /* @__PURE__ */ jsxRuntime.jsx(designSystem.Button, { variant: "tertiary", children: "Cancel" }) }),
            /* @__PURE__ */ jsxRuntime.jsx(
              designSystem.Button,
              {
                onClick: handleCreateClient,
                disabled: !newClient.name || newClient.scopes.length === 0 || !newClient.userDocumentId,
                permission: pluginPermissions.createClient,
                children: "Create"
              }
            )
          ] })
        ] }) }),
        /* @__PURE__ */ jsxRuntime.jsx(designSystem.Modal.Root, { open: isSecretModalOpen, onOpenChange: setIsSecretModalOpen, children: /* @__PURE__ */ jsxRuntime.jsxs(designSystem.Modal.Content, { children: [
          /* @__PURE__ */ jsxRuntime.jsx(designSystem.Modal.Header, { children: /* @__PURE__ */ jsxRuntime.jsx(designSystem.Modal.Title, { children: "Client Credentials" }) }),
          /* @__PURE__ */ jsxRuntime.jsx(designSystem.Modal.Body, { children: createdSecret && /* @__PURE__ */ jsxRuntime.jsxs(
            designSystem.Box,
            {
              background: "neutral100",
              padding: 4,
              hasRadius: true,
              borderColor: "neutral200",
              borderStyle: "solid",
              borderWidth: "1px",
              children: [
                /* @__PURE__ */ jsxRuntime.jsx(designSystem.Typography, { variant: "pi", fontWeight: "bold", marginBottom: 2, children: "⚠️ Save these credentials now! They will not be shown again." }),
                /* @__PURE__ */ jsxRuntime.jsxs(designSystem.Flex, { direction: "column", gap: 3, marginTop: 3, alignItems: "flex-start", children: [
                  /* @__PURE__ */ jsxRuntime.jsxs(designSystem.Box, { width: "100%", children: [
                    /* @__PURE__ */ jsxRuntime.jsx(designSystem.Typography, { variant: "sigma", children: "User ID:" }),
                    /* @__PURE__ */ jsxRuntime.jsxs(designSystem.Flex, { gap: 2, alignItems: "center", marginTop: 1, children: [
                      /* @__PURE__ */ jsxRuntime.jsx(designSystem.Typography, { fontFamily: "monospace", fontSize: 2, children: createdSecret.user.documentId }),
                      /* @__PURE__ */ jsxRuntime.jsx(
                        designSystem.IconButton,
                        {
                          onClick: () => copyToClipboard(createdSecret.user.documentId),
                          label: "Copy",
                          size: "S",
                          withTooltip: false,
                          children: /* @__PURE__ */ jsxRuntime.jsx(icons.Duplicate, {})
                        }
                      )
                    ] })
                  ] }),
                  /* @__PURE__ */ jsxRuntime.jsxs(designSystem.Box, { width: "100%", children: [
                    /* @__PURE__ */ jsxRuntime.jsx(designSystem.Typography, { variant: "sigma", children: "Client ID:" }),
                    /* @__PURE__ */ jsxRuntime.jsxs(designSystem.Flex, { gap: 2, alignItems: "center", marginTop: 1, children: [
                      /* @__PURE__ */ jsxRuntime.jsx(designSystem.Typography, { fontFamily: "monospace", fontSize: 2, children: createdSecret.clientId }),
                      /* @__PURE__ */ jsxRuntime.jsx(
                        designSystem.IconButton,
                        {
                          onClick: () => copyToClipboard(createdSecret.clientId),
                          label: "Copy",
                          size: "S",
                          withTooltip: false,
                          children: /* @__PURE__ */ jsxRuntime.jsx(icons.Duplicate, {})
                        }
                      )
                    ] })
                  ] }),
                  createdSecret.clientSecret && /* @__PURE__ */ jsxRuntime.jsxs(designSystem.Box, { width: "100%", children: [
                    /* @__PURE__ */ jsxRuntime.jsx(designSystem.Typography, { variant: "sigma", children: "Client Secret:" }),
                    /* @__PURE__ */ jsxRuntime.jsxs(designSystem.Flex, { gap: 2, alignItems: "center", marginTop: 1, children: [
                      /* @__PURE__ */ jsxRuntime.jsx(designSystem.Typography, { fontFamily: "monospace", fontSize: 2, children: showSecret ? createdSecret.clientSecret : Array(createdSecret.clientSecret.length).fill("•").join("") }),
                      /* @__PURE__ */ jsxRuntime.jsx(
                        designSystem.IconButton,
                        {
                          onClick: () => setShowSecret(!showSecret),
                          label: showSecret ? "Hide" : "Show",
                          size: "S",
                          withTooltip: false,
                          children: showSecret ? /* @__PURE__ */ jsxRuntime.jsx(icons.EyeStriked, {}) : /* @__PURE__ */ jsxRuntime.jsx(icons.Eye, {})
                        }
                      ),
                      /* @__PURE__ */ jsxRuntime.jsx(
                        designSystem.IconButton,
                        {
                          onClick: () => copyToClipboard(createdSecret.clientSecret),
                          label: "Copy",
                          size: "S",
                          withTooltip: false,
                          children: /* @__PURE__ */ jsxRuntime.jsx(icons.Duplicate, {})
                        }
                      )
                    ] })
                  ] }),
                  createdSecret.privateKey && /* @__PURE__ */ jsxRuntime.jsxs(designSystem.Box, { width: "100%", children: [
                    /* @__PURE__ */ jsxRuntime.jsxs(designSystem.Flex, { justifyContent: "space-between", alignItems: "center", children: [
                      /* @__PURE__ */ jsxRuntime.jsx(designSystem.Typography, { variant: "sigma", children: "Public Key:" }),
                      /* @__PURE__ */ jsxRuntime.jsx(
                        designSystem.IconButton,
                        {
                          onClick: () => copyToClipboard(createdSecret.publicKey),
                          label: "Copy",
                          size: "S",
                          withTooltip: false,
                          children: /* @__PURE__ */ jsxRuntime.jsx(icons.Duplicate, {})
                        }
                      )
                    ] }),
                    /* @__PURE__ */ jsxRuntime.jsx(
                      designSystem.Box,
                      {
                        marginTop: 1,
                        padding: 3,
                        background: "neutral0",
                        hasRadius: true,
                        borderColor: "neutral200",
                        borderStyle: "solid",
                        borderWidth: "1px",
                        children: /* @__PURE__ */ jsxRuntime.jsx(
                          designSystem.Typography,
                          {
                            fontFamily: "monospace",
                            fontSize: 1,
                            style: { whiteSpace: "pre-wrap", wordBreak: "break-all" },
                            children: createdSecret.publicKey
                          }
                        )
                      }
                    )
                  ] }),
                  createdSecret.privateKey && /* @__PURE__ */ jsxRuntime.jsxs(designSystem.Box, { width: "100%", children: [
                    /* @__PURE__ */ jsxRuntime.jsxs(designSystem.Flex, { justifyContent: "space-between", alignItems: "center", children: [
                      /* @__PURE__ */ jsxRuntime.jsx(designSystem.Typography, { variant: "sigma", children: "Private Key:" }),
                      /* @__PURE__ */ jsxRuntime.jsx(
                        designSystem.IconButton,
                        {
                          onClick: () => copyToClipboard(createdSecret.privateKey),
                          label: "Copy",
                          size: "S",
                          withTooltip: false,
                          children: /* @__PURE__ */ jsxRuntime.jsx(icons.Duplicate, {})
                        }
                      )
                    ] }),
                    /* @__PURE__ */ jsxRuntime.jsx(
                      designSystem.Box,
                      {
                        marginTop: 1,
                        padding: 3,
                        background: "neutral0",
                        hasRadius: true,
                        borderColor: "neutral200",
                        borderStyle: "solid",
                        borderWidth: "1px",
                        children: /* @__PURE__ */ jsxRuntime.jsx(
                          designSystem.Typography,
                          {
                            fontFamily: "monospace",
                            fontSize: 1,
                            style: { whiteSpace: "pre-wrap", wordBreak: "break-all" },
                            children: createdSecret.privateKey
                          }
                        )
                      }
                    )
                  ] })
                ] })
              ]
            }
          ) }),
          /* @__PURE__ */ jsxRuntime.jsx(designSystem.Modal.Footer, { children: /* @__PURE__ */ jsxRuntime.jsx(designSystem.Modal.Close, { children: /* @__PURE__ */ jsxRuntime.jsx(designSystem.Button, { variant: "secondary", children: "Close" }) }) })
        ] }) }),
        /* @__PURE__ */ jsxRuntime.jsx(designSystem.Modal.Root, { open: isEditModalOpen, onOpenChange: setIsEditModalOpen, children: /* @__PURE__ */ jsxRuntime.jsxs(designSystem.Modal.Content, { children: [
          /* @__PURE__ */ jsxRuntime.jsx(designSystem.Modal.Header, { children: /* @__PURE__ */ jsxRuntime.jsx(designSystem.Modal.Title, { children: "Edit OAuth Client" }) }),
          /* @__PURE__ */ jsxRuntime.jsx(designSystem.Modal.Body, { children: editingClient && /* @__PURE__ */ jsxRuntime.jsxs(designSystem.Flex, { direction: "column", gap: 4, width: "100%", children: [
            /* @__PURE__ */ jsxRuntime.jsxs(designSystem.Field.Root, { width: "100%", children: [
              /* @__PURE__ */ jsxRuntime.jsx(designSystem.Field.Label, { children: "Name" }),
              /* @__PURE__ */ jsxRuntime.jsx(designSystem.Field.Input, { value: editingClient.name })
            ] }),
            /* @__PURE__ */ jsxRuntime.jsxs(designSystem.Field.Root, { width: "100%", children: [
              /* @__PURE__ */ jsxRuntime.jsx(designSystem.Field.Label, { children: "User" }),
              /* @__PURE__ */ jsxRuntime.jsx(
                designSystem.Field.Input,
                {
                  value: `${editingClient.user.username} (${editingClient.user.email})`,
                  disabled: true
                }
              )
            ] }),
            /* @__PURE__ */ jsxRuntime.jsxs(designSystem.Field.Root, { width: "100%", children: [
              /* @__PURE__ */ jsxRuntime.jsx(designSystem.Field.Label, { children: "Redirect URIs" }),
              /* @__PURE__ */ jsxRuntime.jsxs(designSystem.Flex, { direction: "column", gap: 2, alignItems: "flex-start", width: "100%", children: [
                (editingClient.redirectUris || []).map((uri, index) => /* @__PURE__ */ jsxRuntime.jsxs(designSystem.Flex, { gap: 2, alignItems: "center", width: "50%", children: [
                  /* @__PURE__ */ jsxRuntime.jsx(designSystem.Box, { flex: "1", children: /* @__PURE__ */ jsxRuntime.jsx(
                    designSystem.Field.Input,
                    {
                      value: uri,
                      onChange: (e) => handleEditRedirectUriChange(index, e.target.value),
                      placeholder: "https://example.com/callback"
                    }
                  ) }),
                  (editingClient.redirectUris || []).length > 0 && /* @__PURE__ */ jsxRuntime.jsx(
                    designSystem.IconButton,
                    {
                      label: "Remove",
                      onClick: () => handleEditRemoveRedirectUri(index),
                      variant: "danger-light",
                      withTooltip: false,
                      children: /* @__PURE__ */ jsxRuntime.jsx(icons.Cross, {})
                    }
                  )
                ] }, index)),
                /* @__PURE__ */ jsxRuntime.jsx(
                  designSystem.Button,
                  {
                    variant: "secondary",
                    startIcon: /* @__PURE__ */ jsxRuntime.jsx(icons.Plus, {}),
                    onClick: handleEditAddRedirectUri,
                    size: "S",
                    children: "Add Redirect URI"
                  }
                )
              ] }),
              /* @__PURE__ */ jsxRuntime.jsx(designSystem.Field.Hint, { children: "Authorization callback URLs for OAuth flow" })
            ] }),
            /* @__PURE__ */ jsxRuntime.jsxs(designSystem.Field.Root, { required: true, width: "100%", children: [
              /* @__PURE__ */ jsxRuntime.jsxs(designSystem.Flex, { justifyContent: "space-between", alignItems: "center", marginBottom: 2, children: [
                /* @__PURE__ */ jsxRuntime.jsx(designSystem.Field.Label, { children: "Scopes" }),
                /* @__PURE__ */ jsxRuntime.jsxs(designSystem.Flex, { gap: 2, children: [
                  /* @__PURE__ */ jsxRuntime.jsx(
                    designSystem.Button,
                    {
                      variant: "tertiary",
                      size: "S",
                      onClick: () => {
                        const allScopeNames = Object.values(availableScopes).flat().map((s) => s.name);
                        setEditingClient({ ...editingClient, scopes: allScopeNames });
                      },
                      children: "Select All"
                    }
                  ),
                  /* @__PURE__ */ jsxRuntime.jsx(
                    designSystem.Button,
                    {
                      variant: "tertiary",
                      size: "S",
                      onClick: () => setEditingClient({ ...editingClient, scopes: [] }),
                      children: "Deselect All"
                    }
                  )
                ] })
              ] }),
              /* @__PURE__ */ jsxRuntime.jsx(
                designSystem.Box,
                {
                  maxHeight: "300px",
                  width: "100%",
                  overflow: "auto",
                  padding: 3,
                  background: "neutral100",
                  hasRadius: true,
                  children: /* @__PURE__ */ jsxRuntime.jsx(designSystem.Flex, { direction: "row", gap: 3, wrap: "wrap", alignItems: "flex-start", children: Object.entries(availableScopes).map(([section, scopes]) => {
                    const scopeNames = scopes.map((s) => s.name);
                    const allSelected = scopeNames.every(
                      (scopeName) => editingClient.scopes.includes(scopeName)
                    );
                    const isExpanded = editExpandedSections[section];
                    return /* @__PURE__ */ jsxRuntime.jsx(designSystem.Box, { width: "48%", minWidth: "250px", children: /* @__PURE__ */ jsxRuntime.jsxs(designSystem.Flex, { direction: "column", gap: 2, alignItems: "flex-start", children: [
                      /* @__PURE__ */ jsxRuntime.jsxs(designSystem.Flex, { gap: 2, alignItems: "center", width: "100%", children: [
                        /* @__PURE__ */ jsxRuntime.jsx(
                          designSystem.Checkbox,
                          {
                            checked: allSelected,
                            onCheckedChange: () => handleEditSectionToggle(scopes),
                            children: /* @__PURE__ */ jsxRuntime.jsxs(designSystem.Typography, { fontWeight: "bold", variant: "omega", children: [
                              section,
                              " (",
                              scopes.length,
                              ")"
                            ] })
                          }
                        ),
                        /* @__PURE__ */ jsxRuntime.jsx(
                          designSystem.IconButton,
                          {
                            onClick: () => toggleEditSectionExpand(section),
                            label: isExpanded ? "Collapse" : "Expand",
                            variant: "ghost",
                            size: "S",
                            withTooltip: false,
                            children: isExpanded ? /* @__PURE__ */ jsxRuntime.jsx(icons.ChevronUp, {}) : /* @__PURE__ */ jsxRuntime.jsx(icons.ChevronDown, {})
                          }
                        )
                      ] }),
                      isExpanded && /* @__PURE__ */ jsxRuntime.jsx(designSystem.Box, { paddingLeft: 6, children: /* @__PURE__ */ jsxRuntime.jsx(designSystem.Flex, { direction: "column", gap: 2, alignItems: "flex-start", children: scopes.map((scope) => /* @__PURE__ */ jsxRuntime.jsx(
                        designSystem.Checkbox,
                        {
                          checked: editingClient.scopes.includes(scope.name),
                          onCheckedChange: () => handleEditScopeToggle(scope.name),
                          children: /* @__PURE__ */ jsxRuntime.jsxs(designSystem.Flex, { gap: 2, alignItems: "center", children: [
                            /* @__PURE__ */ jsxRuntime.jsx(
                              designSystem.Box,
                              {
                                paddingLeft: 2,
                                paddingRight: 2,
                                paddingTop: 1,
                                paddingBottom: 1,
                                background: scope.action.includes("find") || scope.action.includes("get") || scope.action.includes("list") ? "success500" : scope.action.includes("update") ? "warning500" : scope.action.includes("delete") || scope.action.includes("remove") || scope.action.includes("destroy") ? "danger500" : "primary500",
                                hasRadius: true,
                                children: /* @__PURE__ */ jsxRuntime.jsx(
                                  designSystem.Typography,
                                  {
                                    variant: "pi",
                                    fontWeight: "bold",
                                    fontSize: 1,
                                    children: scope.action
                                  }
                                )
                              }
                            ),
                            /* @__PURE__ */ jsxRuntime.jsx(designSystem.Typography, { variant: "pi", fontFamily: "monospace", children: scope.name })
                          ] })
                        },
                        scope.name
                      )) }) })
                    ] }) }, section);
                  }) })
                }
              ),
              /* @__PURE__ */ jsxRuntime.jsxs(designSystem.Field.Hint, { children: [
                "Selected: ",
                editingClient.scopes.length,
                " scope(s)"
              ] })
            ] })
          ] }) }),
          /* @__PURE__ */ jsxRuntime.jsxs(designSystem.Modal.Footer, { children: [
            /* @__PURE__ */ jsxRuntime.jsx(designSystem.Modal.Close, { children: /* @__PURE__ */ jsxRuntime.jsx(designSystem.Button, { variant: "tertiary", children: "Cancel" }) }),
            /* @__PURE__ */ jsxRuntime.jsx(
              designSystem.Button,
              {
                onClick: handleUpdateClient,
                disabled: !editingClient || editingClient.scopes.length === 0,
                permission: pluginPermissions.updateClient,
                children: "Update"
              }
            )
          ] })
        ] }) })
      ] })
    ] })
  ] });
};
const AccessTokensPage = () => {
  const { formatDate } = reactIntl.useIntl();
  const { get, post } = admin.useFetchClient();
  const { toggleNotification } = admin.useNotification();
  const navigate = reactRouterDom.useNavigate();
  const { clientDocumentId } = reactRouterDom.useParams();
  const [tokens, setTokens] = react.useState([]);
  const [loading, setLoading] = react.useState(true);
  const [pagination, setPagination] = react.useState({
    page: 1,
    pageSize: 10,
    pageCount: 1,
    total: 0
  });
  const [clientName, setClientName] = react.useState("");
  const fetchTokens = async (page = pagination.page, pageSize = pagination.pageSize) => {
    try {
      setLoading(true);
      const params = qs__default.default.stringify(
        {
          populate: ["client"],
          filters: clientDocumentId ? { client: { documentId: clientDocumentId } } : void 0,
          sort: ["createdAt:desc"],
          pagination: {
            page,
            pageSize
          }
        },
        { encodeValuesOnly: true }
      );
      const response = await get(`/strapi-plugin-oauth2/access-tokens?${params}`);
      const { data, meta } = response.data;
      setTokens(data || []);
      if (meta?.pagination) {
        setPagination(meta.pagination);
      }
      if (data && data.length > 0 && data[0].client) {
        setClientName(data[0].client.name);
      }
    } catch (error) {
      toggleNotification({
        type: "danger",
        message: "Failed to fetch access tokens"
      });
    } finally {
      setLoading(false);
    }
  };
  react.useEffect(() => {
    fetchTokens();
  }, [clientDocumentId]);
  const handleRevokeToken = async (jti) => {
    if (!confirm("Are you sure you want to revoke this access token?")) return;
    try {
      await post(`/strapi-plugin-oauth2/access-tokens/revoke`, {
        jti
      });
      fetchTokens(pagination.page, pagination.pageSize);
      toggleNotification({
        type: "success",
        message: "Access token revoked successfully"
      });
    } catch (error) {
      toggleNotification({
        type: "danger",
        message: "Failed to revoke access token"
      });
    }
  };
  const handlePageChange = (page) => {
    fetchTokens(page, pagination.pageSize);
  };
  const handlePageSizeChange = (pageSize) => {
    fetchTokens(1, parseInt(pageSize));
  };
  const isTokenExpired = (expiresAt) => {
    return new Date(expiresAt) < /* @__PURE__ */ new Date();
  };
  const isTokenRevoked = (revokedAt) => {
    return new Date(revokedAt) < /* @__PURE__ */ new Date();
  };
  const getPaginationPages = () => {
    const MAX_PAGES = 5;
    const { page: activePage, pageCount } = pagination;
    const pages = [];
    if (pageCount <= MAX_PAGES) {
      for (let i = 1; i <= pageCount; i++) {
        pages.push(i);
      }
    } else {
      if (activePage <= 3) {
        pages.push(1, 2, 3, 4, -1, pageCount);
      } else if (activePage >= pageCount - 2) {
        pages.push(1, -1, pageCount - 3, pageCount - 2, pageCount - 1, pageCount);
      } else {
        pages.push(1, -1, activePage - 1, activePage, activePage + 1, -2, pageCount);
      }
    }
    return pages;
  };
  return /* @__PURE__ */ jsxRuntime.jsxs(admin.Layouts.Root, { children: [
    /* @__PURE__ */ jsxRuntime.jsx(admin.Page.Title, { children: "OAuth2 Access Tokens" }),
    /* @__PURE__ */ jsxRuntime.jsxs(admin.Page.Main, { children: [
      /* @__PURE__ */ jsxRuntime.jsx(
        admin.Layouts.Header,
        {
          title: `Access Tokens${clientName ? ` - ${clientName}` : ""}`,
          subtitle: `${pagination.total} token(s) found`,
          navigationAction: /* @__PURE__ */ jsxRuntime.jsx(
            designSystem.Button,
            {
              variant: "tertiary",
              onClick: () => navigate(-1),
              children: "Back"
            }
          )
        }
      ),
      /* @__PURE__ */ jsxRuntime.jsx(admin.Layouts.Content, { children: loading ? /* @__PURE__ */ jsxRuntime.jsx(designSystem.Typography, { children: "Loading..." }) : tokens.length === 0 ? /* @__PURE__ */ jsxRuntime.jsx(designSystem.Box, { padding: 8, background: "neutral0", hasRadius: true, children: /* @__PURE__ */ jsxRuntime.jsx(designSystem.Flex, { justifyContent: "center", children: /* @__PURE__ */ jsxRuntime.jsx(designSystem.Typography, { children: "No access tokens found" }) }) }) : /* @__PURE__ */ jsxRuntime.jsxs(jsxRuntime.Fragment, { children: [
        /* @__PURE__ */ jsxRuntime.jsxs(designSystem.Table, { children: [
          /* @__PURE__ */ jsxRuntime.jsx(designSystem.Thead, { children: /* @__PURE__ */ jsxRuntime.jsxs(designSystem.Tr, { children: [
            /* @__PURE__ */ jsxRuntime.jsx(designSystem.Th, { children: /* @__PURE__ */ jsxRuntime.jsx(designSystem.Typography, { variant: "sigma", children: "Client Name" }) }),
            /* @__PURE__ */ jsxRuntime.jsx(designSystem.Th, { children: /* @__PURE__ */ jsxRuntime.jsx(designSystem.Typography, { variant: "sigma", children: "Client ID" }) }),
            /* @__PURE__ */ jsxRuntime.jsx(designSystem.Th, { children: /* @__PURE__ */ jsxRuntime.jsx(designSystem.Typography, { variant: "sigma", children: "Scopes" }) }),
            /* @__PURE__ */ jsxRuntime.jsx(designSystem.Th, { children: /* @__PURE__ */ jsxRuntime.jsx(designSystem.Typography, { variant: "sigma", children: "Status" }) }),
            /* @__PURE__ */ jsxRuntime.jsx(designSystem.Th, { children: /* @__PURE__ */ jsxRuntime.jsx(designSystem.Typography, { variant: "sigma", children: "Expires At" }) }),
            /* @__PURE__ */ jsxRuntime.jsx(designSystem.Th, { children: /* @__PURE__ */ jsxRuntime.jsx(designSystem.Typography, { variant: "sigma", children: "Created At" }) }),
            /* @__PURE__ */ jsxRuntime.jsx(designSystem.Th, { children: /* @__PURE__ */ jsxRuntime.jsx(designSystem.Typography, { variant: "sigma", children: "Actions" }) })
          ] }) }),
          /* @__PURE__ */ jsxRuntime.jsx(designSystem.Tbody, { children: tokens.map((token) => {
            const expired = isTokenExpired(token.expiresAt);
            const revoked = isTokenRevoked(token.revokedAt);
            const scopes = (token.scope || "").split(" ").filter((s) => s);
            return /* @__PURE__ */ jsxRuntime.jsxs(designSystem.Tr, { children: [
              /* @__PURE__ */ jsxRuntime.jsx(designSystem.Td, { style: { verticalAlign: "top" }, children: /* @__PURE__ */ jsxRuntime.jsx(designSystem.Box, { style: { marginTop: "20px" }, children: /* @__PURE__ */ jsxRuntime.jsx(designSystem.Typography, { fontWeight: "bold", children: token.client?.name || "N/A" }) }) }),
              /* @__PURE__ */ jsxRuntime.jsx(designSystem.Td, { style: { verticalAlign: "top" }, children: /* @__PURE__ */ jsxRuntime.jsx(designSystem.Typography, { variant: "pi", fontFamily: "monospace", textColor: "neutral600", children: token.client?.clientId || "N/A" }) }),
              /* @__PURE__ */ jsxRuntime.jsx(designSystem.Td, { style: { verticalAlign: "middle", maxWidth: "300px" }, children: scopes.length > 0 ? /* @__PURE__ */ jsxRuntime.jsxs(designSystem.Flex, { direction: "column", gap: 1, alignItems: "flex-start", wrap: "wrap", children: [
                scopes.slice(0, 3).map((scope, index) => /* @__PURE__ */ jsxRuntime.jsx(designSystem.Typography, { variant: "pi", fontFamily: "monospace", children: scope }, index)),
                scopes.length > 3 && /* @__PURE__ */ jsxRuntime.jsxs(designSystem.Typography, { variant: "pi", textColor: "neutral600", children: [
                  "+",
                  scopes.length - 3,
                  " more"
                ] })
              ] }) : /* @__PURE__ */ jsxRuntime.jsx(designSystem.Typography, { variant: "pi", children: "No scopes" }) }),
              /* @__PURE__ */ jsxRuntime.jsx(designSystem.Td, { style: { verticalAlign: "top" }, children: expired ? /* @__PURE__ */ jsxRuntime.jsx(designSystem.Badge, { variant: "", children: "Expired" }) : revoked ? /* @__PURE__ */ jsxRuntime.jsx(designSystem.Badge, { variant: "danger", children: "Revoked" }) : /* @__PURE__ */ jsxRuntime.jsx(designSystem.Badge, { active: true, children: "Active" }) }),
              /* @__PURE__ */ jsxRuntime.jsx(designSystem.Td, { style: { verticalAlign: "top" }, children: /* @__PURE__ */ jsxRuntime.jsx(designSystem.Typography, { textColor: expired ? "danger600" : "neutral800", children: formatDate(token.expiresAt, {
                year: "numeric",
                month: "short",
                day: "2-digit",
                hour: "2-digit",
                minute: "2-digit"
              }) }) }),
              /* @__PURE__ */ jsxRuntime.jsx(designSystem.Td, { style: { verticalAlign: "top" }, children: /* @__PURE__ */ jsxRuntime.jsx(designSystem.Typography, { children: formatDate(token.createdAt, {
                year: "numeric",
                month: "short",
                day: "2-digit",
                hour: "2-digit",
                minute: "2-digit"
              }) }) }),
              /* @__PURE__ */ jsxRuntime.jsx(designSystem.Td, { style: { verticalAlign: "top" }, children: !expired && !revoked && /* @__PURE__ */ jsxRuntime.jsx(
                designSystem.IconButton,
                {
                  label: "Revoke Token",
                  onClick: () => handleRevokeToken(token.jti),
                  variant: "danger-light",
                  permission: pluginPermissions.revokeAccessToken,
                  children: /* @__PURE__ */ jsxRuntime.jsx(icons.MinusCircle, {})
                }
              ) })
            ] }, token.documentId);
          }) })
        ] }),
        /* @__PURE__ */ jsxRuntime.jsx(designSystem.Box, { marginTop: 4, children: /* @__PURE__ */ jsxRuntime.jsxs(designSystem.Flex, { justifyContent: "space-between", alignItems: "center", children: [
          /* @__PURE__ */ jsxRuntime.jsxs(
            designSystem.SingleSelect,
            {
              size: "S",
              value: pagination.pageSize.toString(),
              onChange: handlePageSizeChange,
              placeholder: "Page size",
              children: [
                /* @__PURE__ */ jsxRuntime.jsx(designSystem.SingleSelectOption, { value: "10", children: "10 per page" }),
                /* @__PURE__ */ jsxRuntime.jsx(designSystem.SingleSelectOption, { value: "25", children: "25 per page" }),
                /* @__PURE__ */ jsxRuntime.jsx(designSystem.SingleSelectOption, { value: "50", children: "50 per page" }),
                /* @__PURE__ */ jsxRuntime.jsx(designSystem.SingleSelectOption, { value: "100", children: "100 per page" })
              ]
            }
          ),
          /* @__PURE__ */ jsxRuntime.jsxs(
            designSystem.Pagination,
            {
              activePage: pagination.page,
              pageCount: pagination.pageCount,
              onPageChange: handlePageChange,
              children: [
                /* @__PURE__ */ jsxRuntime.jsx(
                  designSystem.PreviousLink,
                  {
                    onClick: () => pagination.page > 1 && handlePageChange(pagination.page - 1),
                    children: "Go to previous page"
                  }
                ),
                getPaginationPages().map((pageNum, index) => {
                  if (pageNum === -1 || pageNum === -2) {
                    return /* @__PURE__ */ jsxRuntime.jsx(designSystem.Dots, { children: "..." }, `dots-${index}`);
                  }
                  return /* @__PURE__ */ jsxRuntime.jsxs(
                    designSystem.PageLink,
                    {
                      number: pageNum,
                      onClick: () => handlePageChange(pageNum),
                      children: [
                        "Go to page ",
                        pageNum
                      ]
                    },
                    pageNum
                  );
                }),
                /* @__PURE__ */ jsxRuntime.jsx(
                  designSystem.NextLink,
                  {
                    onClick: () => pagination.page < pagination.pageCount && handlePageChange(pagination.page + 1),
                    children: "Go to next page"
                  }
                )
              ]
            }
          )
        ] }) })
      ] }) })
    ] })
  ] });
};
const App = () => {
  return /* @__PURE__ */ jsxRuntime.jsxs(reactRouterDom.Routes, { children: [
    /* @__PURE__ */ jsxRuntime.jsx(reactRouterDom.Route, { index: true, element: /* @__PURE__ */ jsxRuntime.jsx(HomePage, {}) }),
    /* @__PURE__ */ jsxRuntime.jsx(reactRouterDom.Route, { path: "access-tokens", element: /* @__PURE__ */ jsxRuntime.jsx(AccessTokensPage, {}) }),
    /* @__PURE__ */ jsxRuntime.jsx(reactRouterDom.Route, { path: "access-tokens/:clientDocumentId", element: /* @__PURE__ */ jsxRuntime.jsx(AccessTokensPage, {}) }),
    /* @__PURE__ */ jsxRuntime.jsx(reactRouterDom.Route, { path: "*", element: /* @__PURE__ */ jsxRuntime.jsx(admin.Page.Error, {}) })
  ] });
};
exports.App = App;
