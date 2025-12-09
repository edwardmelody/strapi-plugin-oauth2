import React, { useState, useEffect } from 'react';
import {
  Main,
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
  Flex,
  SingleSelect,
  SingleSelectOption,
  Pagination,
  Badge,
} from '@strapi/design-system';
import { ArrowLeft, Layout, MinusCircle } from '@strapi/icons';
import { useIntl } from 'react-intl';
import { Layouts, Page, useFetchClient, useNotification } from '@strapi/strapi/admin';
import { useNavigate, useParams } from 'react-router-dom';
import qs from 'qs';
import pluginPermissions from '../permissions';
import { PreviousLink } from '@strapi/design-system';
import { PageLink } from '@strapi/design-system';
import { Dots } from '@strapi/design-system';
import { NextLink } from '@strapi/design-system';

interface AccessToken {
  documentId: string;
  jti: string;
  token: string;
  clientId: string;
  userId: string;
  scope: string;
  expiresAt: string;
  revokedAt: string;
  createdAt: string;
  client: {
    name: string;
    clientId: string;
  };
  usedAt?: string;
}

interface PaginationMeta {
  page: number;
  pageSize: number;
  pageCount: number;
  total: number;
}

const AccessTokensPage = () => {
  const { formatDate } = useIntl();
  const { get, post } = useFetchClient();
  const { toggleNotification } = useNotification();
  const navigate = useNavigate();
  const { clientDocumentId } = useParams<{ clientDocumentId: string }>();

  const [tokens, setTokens] = useState<AccessToken[]>([]);
  const [loading, setLoading] = useState(true);
  const [pagination, setPagination] = useState<PaginationMeta>({
    page: 1,
    pageSize: 10,
    pageCount: 1,
    total: 0,
  });
  const [clientName, setClientName] = useState<string>('');

  const fetchTokens = async (
    page: number = pagination.page,
    pageSize: number = pagination.pageSize
  ) => {
    try {
      setLoading(true);
      const params = qs.stringify(
        {
          populate: ['client'],
          filters: clientDocumentId ? { client: { documentId: clientDocumentId } } : undefined,
          sort: ['createdAt:desc'],
          pagination: {
            page,
            pageSize,
          },
        },
        { encodeValuesOnly: true }
      );
      const response = await get(`/oauth2/access-tokens?${params}`);
      const { data, meta } = response.data;

      setTokens(data || []);
      if (meta?.pagination) {
        setPagination(meta.pagination);
      }

      // Set client name from first token if available
      if (data && data.length > 0 && data[0].client) {
        setClientName(data[0].client.name);
      }
    } catch (error) {
      toggleNotification({
        type: 'danger',
        message: 'Failed to fetch access tokens',
      });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchTokens();
  }, [clientDocumentId]);

  const handleRevokeToken = async (jti: string) => {
    if (!confirm('Are you sure you want to revoke this access token?')) return;

    try {
      await post(`/oauth2/access-tokens/revoke`, {
        jti,
      });
      fetchTokens(pagination.page, pagination.pageSize);
      toggleNotification({
        type: 'success',
        message: 'Access token revoked successfully',
      });
    } catch (error) {
      toggleNotification({
        type: 'danger',
        message: 'Failed to revoke access token',
      });
    }
  };

  const handlePageChange = (page: number) => {
    fetchTokens(page, pagination.pageSize);
  };

  const handlePageSizeChange = (pageSize: string) => {
    fetchTokens(1, parseInt(pageSize));
  };

  const isTokenExpired = (expiresAt: string) => {
    return new Date(expiresAt) < new Date();
  };

  const isTokenRevoked = (revokedAt: string) => {
    return new Date(revokedAt) < new Date();
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
      <Page.Title>OAuth2 Access Tokens</Page.Title>
      <Page.Main>
        <Layouts.Header
          title={`Access Tokens${clientName ? ` - ${clientName}` : ''}`}
          subtitle={`${pagination.total} token(s) found`}
          navigationAction={
            <Button
              variant="tertiary"
              onClick={() => navigate(-1)} // กลับหน้าก่อนหน้า
            >
              Back
            </Button>
          }
        />
        <Layouts.Content>
          {loading ? (
            <Typography>Loading...</Typography>
          ) : tokens.length === 0 ? (
            <Box padding={8} background="neutral0" hasRadius>
              <Flex justifyContent="center">
                <Typography>No access tokens found</Typography>
              </Flex>
            </Box>
          ) : (
            <>
              <Table>
                <Thead>
                  <Tr>
                    <Th>
                      <Typography variant="sigma">Client Name</Typography>
                    </Th>
                    <Th>
                      <Typography variant="sigma">Client ID</Typography>
                    </Th>
                    <Th>
                      <Typography variant="sigma">Scopes</Typography>
                    </Th>
                    <Th>
                      <Typography variant="sigma">Status</Typography>
                    </Th>
                    <Th>
                      <Typography variant="sigma">Expires At</Typography>
                    </Th>
                    <Th>
                      <Typography variant="sigma">Created At</Typography>
                    </Th>
                    <Th>
                      <Typography variant="sigma">Actions</Typography>
                    </Th>
                  </Tr>
                </Thead>
                <Tbody>
                  {tokens.map((token) => {
                    const expired = isTokenExpired(token.expiresAt);
                    const revoked = isTokenRevoked(token.revokedAt);
                    const scopes = (token.scope || '').split(' ').filter((s) => s);
                    return (
                      <Tr key={token.documentId}>
                        <Td style={{ verticalAlign: 'top' }}>
                          <Box style={{ marginTop: '20px' }}>
                            <Typography fontWeight="bold">{token.client?.name || 'N/A'}</Typography>
                          </Box>
                        </Td>
                        <Td style={{ verticalAlign: 'top' }}>
                          <Typography variant="pi" fontFamily="monospace" textColor="neutral600">
                            {token.client?.clientId || 'N/A'}
                          </Typography>
                        </Td>
                        <Td style={{ verticalAlign: 'middle', maxWidth: '300px' }}>
                          {scopes.length > 0 ? (
                            <Flex direction="column" gap={1} alignItems="flex-start" wrap="wrap">
                              {scopes.slice(0, 3).map((scope, index) => (
                                <Typography key={index} variant="pi" fontFamily="monospace">
                                  {scope}
                                </Typography>
                              ))}
                              {scopes.length > 3 && (
                                <Typography variant="pi" textColor="neutral600">
                                  +{scopes.length - 3} more
                                </Typography>
                              )}
                            </Flex>
                          ) : (
                            <Typography variant="pi">No scopes</Typography>
                          )}
                        </Td>
                        <Td style={{ verticalAlign: 'top' }}>
                          {expired ? (
                            <Badge variant="">Expired</Badge>
                          ) : revoked ? (
                            <Badge variant="danger">Revoked</Badge>
                          ) : (
                            <Badge active>Active</Badge>
                          )}
                        </Td>
                        <Td style={{ verticalAlign: 'top' }}>
                          <Typography textColor={expired ? 'danger600' : 'neutral800'}>
                            {formatDate(token.expiresAt, {
                              year: 'numeric',
                              month: 'short',
                              day: '2-digit',
                              hour: '2-digit',
                              minute: '2-digit',
                            })}
                          </Typography>
                        </Td>
                        <Td style={{ verticalAlign: 'top' }}>
                          <Typography>
                            {formatDate(token.createdAt, {
                              year: 'numeric',
                              month: 'short',
                              day: '2-digit',
                              hour: '2-digit',
                              minute: '2-digit',
                            })}
                          </Typography>
                        </Td>
                        <Td style={{ verticalAlign: 'top' }}>
                          {!expired && !revoked && (
                            <IconButton
                              label="Revoke Token"
                              onClick={() => handleRevokeToken(token.jti)}
                              variant="danger-light"
                              permission={pluginPermissions.revokeAccessToken}
                            >
                              <MinusCircle />
                            </IconButton>
                          )}
                        </Td>
                      </Tr>
                    );
                  })}
                </Tbody>
              </Table>

              {
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
              }
            </>
          )}
        </Layouts.Content>
      </Page.Main>
    </Layouts.Root>
  );
};

export { AccessTokensPage };
