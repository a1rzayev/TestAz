import { Platform } from 'react-native';
import Constants from 'expo-constants';

// Environment configuration
const ENV = {
    dev: {
        apiUrl: Platform.select({
            android: 'http://10.0.2.2:5248',
            ios: 'http://localhost:5248',
            default: 'http://localhost:5248'
        }),
        timeout: 10000
    },
    prod: {
        apiUrl: 'https://api.testaz.com', // Replace with your production API URL
        timeout: 15000
    }
};

// Get the current environment
const getEnvironment = () => {
    const isDev = __DEV__;
    return isDev ? ENV.dev : ENV.prod;
};

// Get the base URL for the current environment
const getBaseUrl = () => {
    const env = getEnvironment();
    return env.apiUrl;
};

// API configuration
export const API_CONFIG = {
    //BASE_URL: 'https://testaz-api-gtgthpeqa2h6fkbt.polandcentral-01.azurewebsites.net',
    BASE_URL: 'http://161.97.113.120',
    TIMEOUT: getEnvironment().timeout,
    HEADERS: {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    },
    
    ENDPOINTS: {
        // Auth endpoints
        AUTH: {
            LOGIN: '/api/auth/login',
            REGISTER: '/api/auth/signup',
            REFRESH_TOKEN: '/api/auth/refresh-token',
            LOGOUT: '/api/auth/logout'
        },
        
        // User endpoints
        USERS: {
            BASE: '/api/user',
            BY_EMAIL: (email: string) => `/api/auth/user/${encodeURIComponent(email)}`,
            BY_ID: (id: string) => `/api/auth/user/id/${encodeURIComponent(id)}`,
            PROFILE: '/api/user/profile',
            UPDATE_PROFILE: '/api/user/profile/update'
        },
        
        // Test endpoints
        TESTS: {
            BASE: '/api/test',
            BY_ID: (id: string) => `/api/test/${id}`,
            CREATE: '/api/test/create',
            SUBMIT: (id: string) => `/api/test/${id}/submit`
        },
        
        // Video Course endpoints
        VIDEO_COURSES: {
            BASE: '/api/videocourse',
            BY_ID: (id: string) => `/api/videocourse/${id}`,
            PROGRESS: (id: string) => `/api/videocourse/${id}/progress`
        },
        
        // User Solutions endpoints
        USER_SOLUTIONS: {
            BASE: '/api/usersolution',
            BY_ID: (id: string) => `/api/usersolution/${id}`,
            BY_TEST: (testId: string) => `/api/usersolution/test/${testId}`
        }
    }
};

// Log the current environment and API URL for debugging
console.log('Environment:', __DEV__ ? 'Development' : 'Production');
console.log('API Base URL:', API_CONFIG.BASE_URL); 