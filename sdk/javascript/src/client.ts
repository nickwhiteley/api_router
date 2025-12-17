/**
 * API Translation Platform JavaScript/TypeScript SDK
 */

import axios, { AxiosInstance, AxiosRequestConfig, AxiosResponse } from 'axios';

export interface ClientOptions {
  baseURL: string;
  token?: string;
  version?: string;
  timeout?: number;
  maxRetries?: number;
}

export interface Organisation {
  id: string;
  name: string;
  is_active: boolean;
  created_at: string;
  updated_at: string;
}

export interface OrganisationCreate {
  name: string;
  is_active?: boolean;
}

export interface AuthenticationConfig {
  type: 'api_key' | 'oauth' | 'basic' | 'none';
  parameters?: Record<string, string>;
}

export interface APIConfiguration {
  id?: string;
  organisation_id?: string;
  name: string;
  type: 'REST' | 'SOAP';
  direction: 'inbound' | 'outbound';
  endpoint: string;
  authentication: AuthenticationConfig;
  headers?: Record<string, string>;
  created_at?: string;
  updated_at?: string;
}

export interface Connector {
  id?: string;
  organisation_id?: string;
  name: string;
  inbound_api_id: string;
  outbound_api_id: string;
  python_script: string;
  is_active?: boolean;
  created_at?: string;
  updated_at?: string;
}

export interface User {
  id?: string;
  organisation_id?: string;
  username: string;
  email: string;
  role: string;
  is_active?: boolean;
  created_at?: string;
  updated_at?: string;
}

export interface ComponentHealth {
  status: 'healthy' | 'degraded' | 'unhealthy';
  message: string;
  timestamp: string;
}

export interface SystemHealth {
  status: 'healthy' | 'degraded' | 'unhealthy';
  components: Record<string, ComponentHealth>;
  timestamp: string;
}

export interface UsageAnalytics {
  total_requests: number;
  success_rate: number;
  avg_response_time: number;
  start_time: string;
  end_time: string;
}

export interface ListOptions {
  limit?: number;
  offset?: number;
}

export interface TimeRangeOptions {
  start?: Date;
  end?: Date;
}

export class ATPError extends Error {
  public statusCode?: number;
  public details?: string;

  constructor(message: string, statusCode?: number, details?: string) {
    super(message);
    this.name = 'ATPError';
    this.statusCode = statusCode;
    this.details = details;
  }
}

export class AuthenticationError extends ATPError {
  constructor(message: string = 'Authentication failed') {
    super(message, 401);
    this.name = 'AuthenticationError';
  }
}

export class NotFoundError extends ATPError {
  constructor(message: string = 'Resource not found') {
    super(message, 404);
    this.name = 'NotFoundError';
  }
}

export class ValidationError extends ATPError {
  constructor(message: string = 'Validation failed') {
    super(message, 400);
    this.name = 'ValidationError';
  }
}

export class Client {
  private axios: AxiosInstance;
  private version: string;

  constructor(options: ClientOptions) {
    this.version = options.version || 'v1';
    
    this.axios = axios.create({
      baseURL: `${options.baseURL.replace(/\/$/, '')}/api/${this.version}`,
      timeout: options.timeout || 30000,
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
      },
    });

    // Set authentication token if provided
    if (options.token) {
      this.setToken(options.token);
    }

    // Add response interceptor for error handling
    this.axios.interceptors.response.use(
      (response) => response,
      (error) => {
        if (error.response) {
          const { status, data } = error.response;
          const message = data?.error || error.message;
          const details = data?.details;

          switch (status) {
            case 401:
              throw new AuthenticationError(message);
            case 404:
              throw new NotFoundError(message);
            case 400:
              throw new ValidationError(message);
            default:
              throw new ATPError(message, status, details);
          }
        }
        throw new ATPError(error.message);
      }
    );

    // Add retry logic
    if (options.maxRetries && options.maxRetries > 0) {
      this.setupRetryLogic(options.maxRetries);
    }
  }

  public setToken(token: string): void {
    this.axios.defaults.headers.common['Authorization'] = `Bearer ${token}`;
  }

  private setupRetryLogic(maxRetries: number): void {
    this.axios.interceptors.response.use(
      (response) => response,
      async (error) => {
        const config = error.config;
        
        if (!config || config.__retryCount >= maxRetries) {
          return Promise.reject(error);
        }

        config.__retryCount = config.__retryCount || 0;
        config.__retryCount++;

        // Retry on 5xx errors and network errors
        if (error.response?.status >= 500 || !error.response) {
          const delay = Math.pow(2, config.__retryCount) * 1000; // Exponential backoff
          await new Promise(resolve => setTimeout(resolve, delay));
          return this.axios(config);
        }

        return Promise.reject(error);
      }
    );
  }

  // Organisation Management

  public async createOrganisation(data: OrganisationCreate): Promise<Organisation> {
    const response = await this.axios.post<Organisation>('/organisations', data);
    return response.data;
  }

  public async getOrganisations(): Promise<Organisation[]> {
    const response = await this.axios.get<Organisation[]>('/organisations');
    return response.data;
  }

  public async getOrganisation(id: string): Promise<Organisation> {
    const response = await this.axios.get<Organisation>(`/organisations/${id}`);
    return response.data;
  }

  public async updateOrganisation(id: string, data: Partial<OrganisationCreate>): Promise<Organisation> {
    const response = await this.axios.put<Organisation>(`/organisations/${id}`, data);
    return response.data;
  }

  public async deleteOrganisation(id: string): Promise<void> {
    await this.axios.delete(`/organisations/${id}`);
  }

  // API Configuration Management

  public async createAPIConfiguration(orgId: string, config: APIConfiguration): Promise<APIConfiguration> {
    const response = await this.axios.post<APIConfiguration>(
      `/organisations/${orgId}/api-configurations`,
      config
    );
    return response.data;
  }

  public async getAPIConfigurations(orgId: string): Promise<APIConfiguration[]> {
    const response = await this.axios.get<APIConfiguration[]>(
      `/organisations/${orgId}/api-configurations`
    );
    return response.data;
  }

  public async getAPIConfiguration(id: string): Promise<APIConfiguration> {
    const response = await this.axios.get<APIConfiguration>(`/api-configurations/${id}`);
    return response.data;
  }

  public async updateAPIConfiguration(id: string, config: APIConfiguration): Promise<APIConfiguration> {
    const response = await this.axios.put<APIConfiguration>(`/api-configurations/${id}`, config);
    return response.data;
  }

  public async deleteAPIConfiguration(id: string): Promise<void> {
    await this.axios.delete(`/api-configurations/${id}`);
  }

  public async testAPIConfiguration(id: string, testData: Record<string, any>): Promise<Record<string, any>> {
    const response = await this.axios.post<Record<string, any>>(
      `/api-configurations/${id}/test`,
      testData
    );
    return response.data;
  }

  // Connector Management

  public async createConnector(orgId: string, connector: Connector): Promise<Connector> {
    const response = await this.axios.post<Connector>(
      `/organisations/${orgId}/connectors`,
      connector
    );
    return response.data;
  }

  public async getConnectors(orgId: string): Promise<Connector[]> {
    const response = await this.axios.get<Connector[]>(`/organisations/${orgId}/connectors`);
    return response.data;
  }

  public async getConnector(id: string): Promise<Connector> {
    const response = await this.axios.get<Connector>(`/connectors/${id}`);
    return response.data;
  }

  public async updateConnector(id: string, connector: Connector): Promise<Connector> {
    const response = await this.axios.put<Connector>(`/connectors/${id}`, connector);
    return response.data;
  }

  public async deleteConnector(id: string): Promise<void> {
    await this.axios.delete(`/connectors/${id}`);
  }

  public async updateConnectorScript(id: string, script: string): Promise<void> {
    await this.axios.put(`/connectors/${id}/script`, { script });
  }

  // User Management

  public async createUser(
    orgId: string,
    userData: { username: string; email: string; role: string },
    password: string
  ): Promise<User> {
    const data = { user: { ...userData, is_active: true }, password };
    const response = await this.axios.post<User>(`/organisations/${orgId}/users`, data);
    return response.data;
  }

  public async getUsers(orgId: string): Promise<User[]> {
    const response = await this.axios.get<User[]>(`/organisations/${orgId}/users`);
    return response.data;
  }

  public async getUser(id: string): Promise<User> {
    const response = await this.axios.get<User>(`/users/${id}`);
    return response.data;
  }

  public async updateUser(id: string, user: User): Promise<User> {
    const response = await this.axios.put<User>(`/users/${id}`, user);
    return response.data;
  }

  public async deleteUser(id: string): Promise<void> {
    await this.axios.delete(`/users/${id}`);
  }

  public async changeUserRole(id: string, role: string): Promise<void> {
    await this.axios.put(`/users/${id}/role`, { role });
  }

  public async changeUserPassword(id: string, password: string): Promise<void> {
    await this.axios.put(`/users/${id}/password`, { password });
  }

  public async activateUser(id: string): Promise<void> {
    await this.axios.post(`/users/${id}/activate`);
  }

  public async deactivateUser(id: string): Promise<void> {
    await this.axios.post(`/users/${id}/deactivate`);
  }

  // Monitoring and Analytics

  public async getSystemHealth(): Promise<SystemHealth> {
    const response = await this.axios.get<SystemHealth>('/system/health');
    return response.data;
  }

  public async getOrganisationMetrics(orgId: string): Promise<Record<string, any>> {
    const response = await this.axios.get<Record<string, any>>(`/organisations/${orgId}/metrics`);
    return response.data;
  }

  public async getUsageAnalytics(options?: TimeRangeOptions): Promise<UsageAnalytics> {
    const params: Record<string, string> = {};
    if (options?.start) {
      params.start = options.start.toISOString();
    }
    if (options?.end) {
      params.end = options.end.toISOString();
    }

    const response = await this.axios.get<UsageAnalytics>('/analytics/usage', { params });
    return response.data;
  }

  public async getRateLimitAnalytics(options?: TimeRangeOptions): Promise<Record<string, any>> {
    const params: Record<string, string> = {};
    if (options?.start) {
      params.start = options.start.toISOString();
    }
    if (options?.end) {
      params.end = options.end.toISOString();
    }

    const response = await this.axios.get<Record<string, any>>('/analytics/rate-limits', { params });
    return response.data;
  }

  public async getOrganisationLogs(
    orgId: string,
    options?: ListOptions
  ): Promise<Record<string, any>[]> {
    const params: Record<string, string> = {};
    if (options?.limit) {
      params.limit = options.limit.toString();
    }
    if (options?.offset) {
      params.offset = options.offset.toString();
    }

    const response = await this.axios.get<Record<string, any>[]>(
      `/organisations/${orgId}/logs`,
      { params }
    );
    return response.data;
  }

  public async getOrganisationErrors(
    orgId: string,
    options?: ListOptions
  ): Promise<Record<string, any>[]> {
    const params: Record<string, string> = {};
    if (options?.limit) {
      params.limit = options.limit.toString();
    }
    if (options?.offset) {
      params.offset = options.offset.toString();
    }

    const response = await this.axios.get<Record<string, any>[]>(
      `/organisations/${orgId}/errors`,
      { params }
    );
    return response.data;
  }

  public async getSystemMetrics(): Promise<Record<string, any>> {
    const response = await this.axios.get<Record<string, any>>('/system/metrics');
    return response.data;
  }

  public async getSystemLogs(options?: ListOptions): Promise<Record<string, any>[]> {
    const params: Record<string, string> = {};
    if (options?.limit) {
      params.limit = options.limit.toString();
    }
    if (options?.offset) {
      params.offset = options.offset.toString();
    }

    const response = await this.axios.get<Record<string, any>[]>('/system/logs', { params });
    return response.data;
  }

  // Audit Logs

  public async getAuditLogs(
    orgId: string,
    options?: ListOptions
  ): Promise<Record<string, any>[]> {
    const params: Record<string, string> = {};
    if (options?.limit) {
      params.limit = options.limit.toString();
    }
    if (options?.offset) {
      params.offset = options.offset.toString();
    }

    const response = await this.axios.get<Record<string, any>[]>(
      `/organisations/${orgId}/audit-logs`,
      { params }
    );
    return response.data;
  }

  public async getResourceAuditLogs(
    resourceId: string,
    options?: ListOptions
  ): Promise<Record<string, any>[]> {
    const params: Record<string, string> = {};
    if (options?.limit) {
      params.limit = options.limit.toString();
    }
    if (options?.offset) {
      params.offset = options.offset.toString();
    }

    const response = await this.axios.get<Record<string, any>[]>(
      `/configurations/${resourceId}/audit-logs`,
      { params }
    );
    return response.data;
  }

  // Configuration Management

  public async getConfigurationVersions(configId: string): Promise<Record<string, any>[]> {
    const response = await this.axios.get<Record<string, any>[]>(
      `/configurations/${configId}/versions`
    );
    return response.data;
  }

  public async getConfigurationVersion(versionId: string): Promise<Record<string, any>> {
    const response = await this.axios.get<Record<string, any>>(
      `/configurations/versions/${versionId}`
    );
    return response.data;
  }

  public async rollbackToVersion(versionId: string): Promise<void> {
    await this.axios.post(`/configurations/versions/${versionId}/rollback`);
  }

  public async synchronizeConfiguration(instanceId: string): Promise<void> {
    await this.axios.post(`/system/sync/${instanceId}`);
  }

  public async getConfigurationChecksum(orgId: string): Promise<string> {
    const response = await this.axios.get<{ checksum: string }>(`/organisations/${orgId}/checksum`);
    return response.data.checksum;
  }

  public async validateConfigurationConsistency(): Promise<void> {
    await this.axios.post('/system/validate-consistency');
  }

  // Utility Methods

  public async ping(): Promise<boolean> {
    try {
      await this.getSystemHealth();
      return true;
    } catch {
      return false;
    }
  }
}