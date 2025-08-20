# PacifiTRAX - Coffee Order Processing System

## Project Structure

```
JAVAtrax/
├── frontend/                # React + Vite application
│   ├── src/
│   │   ├── components/      # Reusable UI components
│   │   ├── pages/           # Main application pages
│   │   ├── hooks/           # Custom React hooks
│   │   ├── utils/           # Helper functions
│   │   ├── types/           # TypeScript type definitions
│   │   └── main.tsx         # Application entry point
│   ├── package.json
│   ├── vite.config.ts
│   └── tailwind.config.js
├── backend/                  # Node.js Express API
│   ├── src/
│   │   ├── routes/          # API route handlers
│   │   ├── services/        # Business logic
│   │   ├── models/          # Database models
│   │   ├── middleware/      # Authentication & validation
│   │   ├── utils/           # Helper functions
│   │   └── server.ts        # Server entry point
│   ├── package.json
│   └── .env.example
├── database/
│   ├── migrations/          # Database schema migrations
│   └── seeds/               # Test data
└── README.md
```

## Backend Implementation

### 1. Package Setup (backend/package.json)

```json
{
  "name": "pacifitrax-backend",
  "version": "1.0.0",
  "scripts": {
    "dev": "tsx watch src/server.ts",
    "build": "tsc",
    "start": "node dist/server.js"
  },
  "dependencies": {
    "express": "^4.18.2",
    "cors": "^2.8.5",
    "helmet": "^7.0.0",
    "bcryptjs": "^2.4.3",
    "jsonwebtoken": "^9.0.2",
    "googleapis": "^126.0.1",
    "sqlite3": "^5.1.6",
    "knex": "^3.0.1",
    "pdfkit": "^0.14.0",
    "dotenv": "^16.3.1",
    "express-rate-limit": "^6.10.0",
    "express-validator": "^7.0.1"
  },
  "devDependencies": {
    "@types/node": "^20.5.0",
    "@types/express": "^4.17.17",
    "@types/bcryptjs": "^2.4.2",
    "@types/jsonwebtoken": "^9.0.2",
    "@types/pdfkit": "^0.12.12",
    "typescript": "^5.1.6",
    "tsx": "^3.12.7"
  }
}
```

### 2. Environment Configuration (.env.example)

```env
# Server Configuration
PORT=3001
NODE_ENV=development
JWT_SECRET=your-super-secret-jwt-key-here

# Database
DATABASE_URL=./database/pacifitrax.db

# Google Sheets API
GOOGLE_SHEETS_PRIVATE_KEY="-----BEGIN PRIVATE KEY-----\nYOUR_PRIVATE_KEY_HERE\n-----END PRIVATE KEY-----\n"
GOOGLE_SHEETS_CLIENT_EMAIL=your-service-account@project.iam.gserviceaccount.com
GOOGLE_SHEETS_SPREADSHEET_ID=1A2B3C4D5E6F7G8H9I0J

# Application Settings
ADMIN_PASSWORD=your-admin-password
COMPANY_NAME=Pacific Coffee Roasters
COMPANY_ADDRESS=123 Roaster St, Coffee City, CA 90210
COMPANY_PHONE=(555) 123-4567
COMPANY_EMAIL=orders@pacificcoffee.com
```

### 3. Database Schema (database/migrations/001_initial.sql)

```sql
-- Users table (for future multi-user support)
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT DEFAULT 'admin',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Customers cache (synced from Google Sheets)
CREATE TABLE customers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT,
    phone TEXT,
    address TEXT,
    discount_percentage REAL DEFAULT 0,
    last_synced DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Products cache (synced from Google Sheets)
CREATE TABLE products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sku TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    price_per_lb REAL NOT NULL,
    description TEXT,
    last_synced DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Orders
CREATE TABLE orders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    order_number TEXT UNIQUE NOT NULL,
    customer_id INTEGER NOT NULL,
    customer_name TEXT NOT NULL,
    customer_email TEXT,
    customer_address TEXT,
    subtotal REAL NOT NULL,
    tax_rate REAL DEFAULT 0.0875,
    tax_amount REAL NOT NULL,
    total REAL NOT NULL,
    delivery_date DATE,
    delivery_instructions TEXT,
    notes TEXT,
    status TEXT DEFAULT 'draft',
    invoice_path TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (customer_id) REFERENCES customers (id)
);

-- Order line items
CREATE TABLE order_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    order_id INTEGER NOT NULL,
    product_id INTEGER NOT NULL,
    sku TEXT NOT NULL,
    product_name TEXT NOT NULL,
    quantity REAL NOT NULL,
    unit_price REAL NOT NULL,
    line_total REAL NOT NULL,
    FOREIGN KEY (order_id) REFERENCES orders (id) ON DELETE CASCADE,
    FOREIGN KEY (product_id) REFERENCES products (id)
);

-- Create indexes for better performance
CREATE INDEX idx_orders_customer_id ON orders(customer_id);
CREATE INDEX idx_orders_created_at ON orders(created_at);
CREATE INDEX idx_orders_status ON orders(status);
CREATE INDEX idx_order_items_order_id ON order_items(order_id);
```

### 4. Server Setup (backend/src/server.ts)

```typescript
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import dotenv from 'dotenv';
import rateLimit from 'express-rate-limit';
import path from 'path';

import authRoutes from './routes/auth';
import customerRoutes from './routes/customers';
import productRoutes from './routes/products';
import orderRoutes from './routes/orders';
import reportRoutes from './routes/reports';
import { initializeDatabase } from './utils/database';
import { authenticateToken } from './middleware/auth';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3001;

// Security middleware
app.use(helmet());
app.use(cors({
  origin: process.env.NODE_ENV === 'production' 
    ? ['https://your-domain.com'] 
    : ['http://localhost:5173'],
  credentials: true
}));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // limit each IP to 100 requests per windowMs
});
app.use(limiter);

// Body parsing
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Serve static files (for invoice PDFs)
app.use('/invoices', express.static(path.join(__dirname, '../invoices')));

// Routes
app.use('/api/auth', authRoutes);
app.use('/api/customers', authenticateToken, customerRoutes);
app.use('/api/products', authenticateToken, productRoutes);
app.use('/api/orders', authenticateToken, orderRoutes);
app.use('/api/reports', authenticateToken, reportRoutes);

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Error handling
app.use((err: any, req: express.Request, res: express.Response, next: express.NextFunction) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Something went wrong!' });
});

// Initialize database and start server
async function startServer() {
  try {
    await initializeDatabase();
    app.listen(PORT, () => {
      console.log(`🚀 PacifiTRAX server running on port ${PORT}`);
    });
  } catch (error) {
    console.error('Failed to start server:', error);
    process.exit(1);
  }
}

startServer();
```

### 5. Authentication Middleware (backend/src/middleware/auth.ts)

```typescript
import jwt from 'jsonwebtoken';
import { Request, Response, NextFunction } from 'express';

export interface AuthRequest extends Request {
  userId?: number;
  username?: string;
}

export const authenticateToken = (req: AuthRequest, res: Response, next: NextFunction) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, process.env.JWT_SECRET!, (err: any, decoded: any) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    
    req.userId = decoded.userId;
    req.username = decoded.username;
    next();
  });
};
```

### 6. Google Sheets Service (backend/src/services/googleSheets.ts)

```typescript
import { google } from 'googleapis';

class GoogleSheetsService {
  private sheets: any;
  
  constructor() {
    const auth = new google.auth.GoogleAuth({
      credentials: {
        type: 'service_account',
        private_key: process.env.GOOGLE_SHEETS_PRIVATE_KEY?.replace(/\\n/g, '\n'),
        client_email: process.env.GOOGLE_SHEETS_CLIENT_EMAIL,
      },
      scopes: ['https://www.googleapis.com/auth/spreadsheets.readonly'],
    });
    
    this.sheets = google.sheets({ version: 'v4', auth });
  }

  async getCustomers() {
    try {
      const response = await this.sheets.spreadsheets.values.get({
        spreadsheetId: process.env.GOOGLE_SHEETS_SPREADSHEET_ID,
        range: 'Customers!A2:F', // Assuming: Name, Email, Phone, Address, Discount%
      });

      const rows = response.data.values || [];
      return rows.map((row: any[], index: number) => ({
        id: index + 1,
        name: row[0] || '',
        email: row[1] || '',
        phone: row[2] || '',
        address: row[3] || '',
        discount_percentage: parseFloat(row[4]) || 0,
      }));
    } catch (error) {
      console.error('Error fetching customers from Google Sheets:', error);
      throw new Error('Failed to sync customers from Google Sheets');
    }
  }

  async getProducts() {
    try {
      const response = await this.sheets.spreadsheets.values.get({
        spreadsheetId: process.env.GOOGLE_SHEETS_SPREADSHEET_ID,
        range: 'Products!A2:D', // Assuming: SKU, Name, Price per lb, Description
      });

      const rows = response.data.values || [];
      return rows.map((row: any[], index: number) => ({
        id: index + 1,
        sku: row[0] || '',
        name: row[1] || '',
        price_per_lb: parseFloat(row[2]) || 0,
        description: row[3] || '',
      }));
    } catch (error) {
      console.error('Error fetching products from Google Sheets:', error);
      throw new Error('Failed to sync products from Google Sheets');
    }
  }
}

export default new GoogleSheetsService();
```

### 7. Database Utility (backend/src/utils/database.ts)

```typescript
import sqlite3 from 'sqlite3';
import { open, Database } from 'sqlite';
import fs from 'fs';
import path from 'path';

let db: Database<sqlite3.Database, sqlite3.Statement>;

export async function initializeDatabase() {
  // Ensure database directory exists
  const dbDir = path.dirname(process.env.DATABASE_URL || './database/pacifitrax.db');
  if (!fs.existsSync(dbDir)) {
    fs.mkdirSync(dbDir, { recursive: true });
  }

  db = await open({
    filename: process.env.DATABASE_URL || './database/pacifitrax.db',
    driver: sqlite3.Database
  });

  // Run migrations
  const migrationPath = path.join(__dirname, '../../database/migrations/001_initial.sql');
  if (fs.existsSync(migrationPath)) {
    const migration = fs.readFileSync(migrationPath, 'utf8');
    await db.exec(migration);
  }

  console.log('✅ Database initialized');
  return db;
}

export function getDatabase() {
  if (!db) {
    throw new Error('Database not initialized');
  }
  return db;
}
```

### 8. PDF Invoice Generator (backend/src/services/pdfGenerator.ts)

```typescript
import PDFDocument from 'pdfkit';
import fs from 'fs';
import path from 'path';

interface InvoiceData {
  orderNumber: string;
  customerName: string;
  customerEmail: string;
  customerAddress: string;
  items: Array<{
    sku: string;
    productName: string;
    quantity: number;
    unitPrice: number;
    lineTotal: number;
  }>;
  subtotal: number;
  taxRate: number;
  taxAmount: number;
  total: number;
  deliveryDate?: string;
  deliveryInstructions?: string;
  notes?: string;
}

export class PDFInvoiceGenerator {
  async generateInvoice(invoiceData: InvoiceData): Promise<string> {
    const doc = new PDFDocument({ margin: 50 });
    
    // Ensure invoices directory exists
    const invoicesDir = path.join(__dirname, '../../invoices');
    if (!fs.existsSync(invoicesDir)) {
      fs.mkdirSync(invoicesDir, { recursive: true });
    }
    
    const fileName = `invoice-${invoiceData.orderNumber}.pdf`;
    const filePath = path.join(invoicesDir, fileName);
    
    doc.pipe(fs.createWriteStream(filePath));

    // Header
    doc.fontSize(20).text(process.env.COMPANY_NAME || 'Pacific Coffee Roasters', 50, 50);
    doc.fontSize(10)
       .text(process.env.COMPANY_ADDRESS || '', 50, 80)
       .text(process.env.COMPANY_PHONE || '', 50, 95)
       .text(process.env.COMPANY_EMAIL || '', 50, 110);

    // Invoice title and number
    doc.fontSize(16).text('INVOICE', 400, 50);
    doc.fontSize(12).text(`Invoice #: ${invoiceData.orderNumber}`, 400, 80);
    doc.text(`Date: ${new Date().toLocaleDateString()}`, 400, 100);

    // Customer information
    doc.fontSize(12).text('Bill To:', 50, 150);
    doc.fontSize(10)
       .text(invoiceData.customerName, 50, 170)
       .text(invoiceData.customerEmail, 50, 185)
       .text(invoiceData.customerAddress, 50, 200);

    // Delivery information
    if (invoiceData.deliveryDate) {
      doc.text(`Delivery Date: ${invoiceData.deliveryDate}`, 400, 150);
    }

    // Line items table
    let yPosition = 250;
    
    // Table headers
    doc.fontSize(10).text('SKU', 50, yPosition);
    doc.text('Product', 100, yPosition);
    doc.text('Qty (lbs)', 300, yPosition);
    doc.text('Unit Price', 380, yPosition);
    doc.text('Total', 450, yPosition);
    
    // Draw line under headers
    yPosition += 15;
    doc.moveTo(50, yPosition).lineTo(500, yPosition).stroke();
    yPosition += 10;

    // Line items
    invoiceData.items.forEach((item) => {
      doc.text(item.sku, 50, yPosition);
      doc.text(item.productName, 100, yPosition);
      doc.text(item.quantity.toString(), 300, yPosition);
      doc.text(`$${item.unitPrice.toFixed(2)}`, 380, yPosition);
      doc.text(`$${item.lineTotal.toFixed(2)}`, 450, yPosition);
      yPosition += 20;
    });

    // Totals
    yPosition += 10;
    doc.moveTo(350, yPosition).lineTo(500, yPosition).stroke();
    yPosition += 15;
    
    doc.text(`Subtotal: $${invoiceData.subtotal.toFixed(2)}`, 350, yPosition);
    yPosition += 15;
    doc.text(`Tax (${(invoiceData.taxRate * 100).toFixed(2)}%): $${invoiceData.taxAmount.toFixed(2)}`, 350, yPosition);
    yPosition += 15;
    doc.fontSize(12).text(`Total: $${invoiceData.total.toFixed(2)}`, 350, yPosition);

    // Delivery instructions
    if (invoiceData.deliveryInstructions) {
      yPosition += 40;
      doc.fontSize(10).text('Delivery Instructions:', 50, yPosition);
      doc.text(invoiceData.deliveryInstructions, 50, yPosition + 15);
    }

    // Notes
    if (invoiceData.notes) {
      yPosition += 40;
      doc.fontSize(10).text('Notes:', 50, yPosition);
      doc.text(invoiceData.notes, 50, yPosition + 15);
    }

    doc.end();

    return new Promise((resolve, reject) => {
      doc.on('end', () => resolve(fileName));
      doc.on('error', reject);
    });
  }
}

export default new PDFInvoiceGenerator();
```

## Frontend Implementation

### 1. Package Setup (frontend/package.json)

```json
{
  "name": "pacifitrax-frontend",
  "version": "1.0.0",
  "type": "module",
  "scripts": {
    "dev": "vite",
    "build": "tsc && vite build",
    "preview": "vite preview"
  },
  "dependencies": {
    "react": "^18.2.0",
    "react-dom": "^18.2.0",
    "react-router-dom": "^6.15.0",
    "axios": "^1.5.0",
    "@headlessui/react": "^1.7.17",
    "@heroicons/react": "^2.0.18",
    "react-hook-form": "^7.45.4",
    "react-query": "^3.39.3",
    "date-fns": "^2.30.0",
    "clsx": "^2.0.0"
  },
  "devDependencies": {
    "@types/react": "^18.2.15",
    "@types/react-dom": "^18.2.7",
    "@vitejs/plugin-react": "^4.0.3",
    "autoprefixer": "^10.4.14",
    "postcss": "^8.4.27",
    "tailwindcss": "^3.3.3",
    "typescript": "^5.0.2",
    "vite": "^4.4.5"
  }
}
```

### 2. Vite Configuration (frontend/vite.config.ts)

```typescript
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/api': {
        target: 'http://localhost:3001',
        changeOrigin: true
      }
    }
  }
})
```

### 3. Main App Component (frontend/src/App.tsx)

```tsx
import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from 'react-query';
import { AuthProvider, useAuth } from './contexts/AuthContext';
import Layout from './components/Layout';
import Login from './pages/Login';
import Dashboard from './pages/Dashboard';
import Orders from './pages/Orders';
import OrderForm from './pages/OrderForm';
import Reports from './pages/Reports';
import './index.css';

const queryClient = new QueryClient();

function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const { isAuthenticated } = useAuth();
  return isAuthenticated ? <>{children}</> : <Navigate to="/login" />;
}

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <AuthProvider>
        <Router>
          <div className="App">
            <Routes>
              <Route path="/login" element={<Login />} />
              <Route path="/" element={
                <ProtectedRoute>
                  <Layout>
                    <Dashboard />
                  </Layout>
                </ProtectedRoute>
              } />
              <Route path="/orders" element={
                <ProtectedRoute>
                  <Layout>
                    <Orders />
                  </Layout>
                </ProtectedRoute>
              } />
              <Route path="/orders/new" element={
                <ProtectedRoute>
                  <Layout>
                    <OrderForm />
                  </Layout>
                </ProtectedRoute>
              } />
              <Route path="/orders/edit/:id" element={
                <ProtectedRoute>
                  <Layout>
                    <OrderForm />
                  </Layout>
                </ProtectedRoute>
              } />
              <Route path="/reports" element={
                <ProtectedRoute>
                  <Layout>
                    <Reports />
                  </Layout>
                </ProtectedRoute>
              } />
            </Routes>
          </div>
        </Router>
      </AuthProvider>
    </QueryClientProvider>
  );
}

export default App;
```

### 4. Authentication Context (frontend/src/contexts/AuthContext.tsx)

```tsx
import React, { createContext, useContext, useEffect, useState } from 'react';
import axios from 'axios';

interface AuthContextType {
  isAuthenticated: boolean;
  user: any;
  login: (username: string, password: string) => Promise<void>;
  logout: () => void;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [user, setUser] = useState(null);

  useEffect(() => {
    const token = localStorage.getItem('token');
    if (token) {
      axios.defaults.headers.common['Authorization'] = `Bearer ${token}`;
      setIsAuthenticated(true);
      // You could verify the token here
    }
  }, []);

  const login = async (username: string, password: string) => {
    try {
      const response = await axios.post('/api/auth/login', { username, password });
      const { token, user } = response.data;
      
      localStorage.setItem('token', token);
      axios.defaults.headers.common['Authorization'] = `Bearer ${token}`;
      
      setIsAuthenticated(true);
      setUser(user);
    } catch (error) {
      throw error;
    }
  };

  const logout = () => {
    localStorage.removeItem('token');
    delete axios.defaults.headers.common['Authorization'];
    setIsAuthenticated(false);
    setUser(null);
  };

  return (
    <AuthContext.Provider value={{ isAuthenticated, user, login, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}
```

### 5. Main Layout Component (frontend/src/components/Layout.tsx)

```tsx
import React from 'react';
import { Link, useLocation } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import {
  HomeIcon,
  DocumentTextIcon,
  ChartBarIcon,
  ArrowRightOnRectangleIcon,
} from '@heroicons/react/24/outline';

const navigation = [
  { name: 'Dashboard', href: '/', icon: HomeIcon },
  { name: 'Orders', href: '/orders', icon: DocumentTextIcon },
  { name: 'Reports', href: '/reports', icon: ChartBarIcon },
];

export default function Layout({ children }: { children: React.ReactNode }) {
  const { logout } = useAuth();
  const location = useLocation();

  return (
    <div className="min-h-screen bg-gray-50">
      <div className="flex">
        {/* Sidebar */}
        <div className="fixed inset-y-0 left-0 z-50 w-64 bg-white shadow-lg">
          <div className="flex h-16 items-center justify-center border-b border-gray-200">
            <h1 className="text-xl font-bold text-gray-900">PacifiTRAX</h1>
          </div>
          
          <nav className="mt-6 px-4">
            <ul className="space-y-2">
              {navigation.map((item) => {
                const isActive = location.pathname === item.href;
                return (
                  <li key={item.name}>
                    <Link
                      to={item.href}
                      className={`group flex items-center px-3 py-2 text-sm font-medium rounded-md ${
                        isActive
                          ? 'bg-blue-100 text-blue-700'
                          : 'text-gray-700 hover:bg-gray-100'
                      }`}
                    >
                      <item.icon className="mr-3 h-5 w-5" />
                      {item.name}
                    </Link>
                  </li>
                );
              })}
            </ul>
          </nav>

          <div className="absolute bottom-0 w-full p-4">
            <button
              onClick={logout}
              className="flex w-full items-center px-3 py-2 text-sm font-medium text-gray-700 rounded-md hover:bg-gray-100"
            >
              <ArrowRightOnRectangleIcon className="mr-3 h-5 w-5" />
              Sign out
            </button>
          </div>
        </div>

        {/* Main content */}
        <div className="ml-64 flex-1">
          <main className="p-8">
            {children}
          </main>
        </div>
      </div>
    </div>
  );
}
```

### 6. Order Form Component (frontend/src/pages/OrderForm.tsx)

```tsx
import React, { useState, useEffect } from 'react';
import { useForm, useFieldArray } from 'react-hook-form';
import { useNavigate, useParams } from 'react-router-dom';
import { useQuery, useMutation } from 'react-query';
import axios from 'axios';
import { PlusIcon, TrashIcon } from '@heroicons/react/24/outline';

interface OrderFormData {
  customerId: number;
  items: Array<{
    productId: number;
    quantity: number;
  }>;
  deliveryDate: string;
  deliveryInstructions: string;
  notes: string;
}

export default function OrderForm() {
  const navigate = useNavigate();
  const { id } = useParams();
  const isEdit = Boolean(id);

  const { register, control, handleSubmit, watch, setValue, formState: { errors } } = useForm<OrderFormData>({
    defaultValues: {
      items: [{ productId: 0, quantity: 1 }]
    }
  });

  const { fields, append, remove } = useFieldArray({
    control,
    name: 'items'
  });

  // Fetch customers and products
  const { data: customers } = useQuery('customers', () => 
    axios.get('/api/customers').then(res => res.data)
  );
  
  const { data: products } = useQuery('products', () => 
    axios.get('/api/products').then(res => res.data)
  );

  // Fetch existing order if editing
  const { data: order } = useQuery(
    ['order', id],
    () => axios.get(`/api/orders/${id}`).then(res => res.data),
    { enabled: isEdit }
  );

  // Calculate totals
  const watchedItems = watch('items');
  const watchedCustomerId = watch('customerId');
  
  const [orderSummary, setOrderSummary] = useState({
    subtotal: 0,
    discount: 0,
    taxAmount: 0,
    total: 0
  });

  useEffect(() => {
    if (products && customers && watchedItems) {
      const customer = customers.find((c: any) => c.id === Number(watchedCustomerId));
      const discountRate = customer?.discount_percentage || 0;
      
      const subtotal = watchedItems.reduce((sum, item) => {
        const product = products.find((p: any) => p.id === Number(item.productId));
        return sum + (product?.price_per_lb || 0) * (item.quantity || 0);
      }, 0);
      
      const discount = subtotal * (discountRate / 100);
      const discountedSubtotal = subtotal - discount;
      const taxAmount = discountedSubtotal * 0.0875; // 8.75% tax
      const total = discountedSubtotal + taxAmount;
      
      setOrderSummary({ subtotal, discount, taxAmount, total });
    }
  }, [watchedItems, watchedCustomerId, products, customers]);

  const createOrderMutation = useMutation(
    (data: OrderFormData) => axios.post('/api/orders', data),
    {
      onSuccess: () => {
        navigate('/orders');
      }
    }
  );

  const updateOrderMutation =
import React, { useState, useEffect } from 'react';
import { useForm, useFieldArray } from 'react-hook-form';
import { useNavigate, useParams } from 'react-router-dom';
import { useQuery, useMutation } from 'react-query';
import axios from 'axios';
import { PlusIcon, TrashIcon } from '@heroicons/react/24/outline';

interface OrderFormData {
  customerId: number;
  items: Array<{
    productId: number;
    quantity: number;
  }>;
  deliveryDate: string;
  deliveryInstructions: string;
  notes: string;
}

export default function OrderForm() {
  const navigate = useNavigate();
  const { id } = useParams();
  const isEdit = Boolean(id);

  const { register, control, handleSubmit, watch, setValue, formState: { errors } } = useForm<OrderFormData>({
    defaultValues: {
      items: [{ productId: 0, quantity: 1 }],
      customerId: 0,
      deliveryDate: '',
      deliveryInstructions: '',
      notes: ''
    }
  });

  const { fields, append, remove } = useFieldArray({
    control,
    name: 'items'
  });

  // Fetch customers and products
  const { data: customers } = useQuery('customers', () =>
    axios.get('/api/customers').then(res => res.data),
    { enabled: true }
  );

  const { data: products } = useQuery('products', () =>
    axios.get('/api/products').then(res => res.data),
    { enabled: true }
  );

  // Fetch existing order if editing
  const { data: order } = useQuery(
    ['order', id],
    () => axios.get(`/api/orders/${id}`).then(res => res.data),
    {
      enabled: isEdit,
      onSuccess: (data) => {
        // Populate form with existing order data
        setValue('customerId', data.customer_id);
        setValue('items', data.items.map((item: any) => ({
          productId: item.product_id,
          quantity: item.quantity
        })));
        setValue('deliveryDate', data.delivery_date || '');
        setValue('deliveryInstructions', data.delivery_instructions || '');
        setValue('notes', data.notes || '');
      }
    }
  );

  // Calculate totals
  const watchedItems = watch('items');
  const watchedCustomerId = watch('customerId');

  const [orderSummary, setOrderSummary] = useState({
    subtotal: 0,
    discount: 0,
    taxAmount: 0,
    total: 0
  });

  useEffect(() => {
    if (products && customers && watchedItems && watchedCustomerId) {
      const customer = customers.find((c: any) => c.id === Number(watchedCustomerId));
      const discountRate = customer?.discount_percentage || 0;

      const subtotal = watchedItems.reduce((sum, item) => {
        const product = products.find((p: any) => p.id === Number(item.productId));
        return sum + (product?.price_per_lb || 0) * (item.quantity || 0);
      }, 0);

      const discount = subtotal * (discountRate / 100);
      const discountedSubtotal = subtotal - discount;
      const taxAmount = discountedSubtotal * 0.0875; // 8.75% tax
      const total = discountedSubtotal + taxAmount;

      setOrderSummary({ subtotal, discount, taxAmount, total });
    }
  }, [watchedItems, watchedCustomerId, products, customers]);

  const createOrderMutation = useMutation(
    (data: OrderFormData) => axios.post('/api/orders', data),
    {
      onSuccess: () => {
        navigate('/orders');
      },
      onError: (error: any) => {
        console.error('Error creating order:', error);
        alert('Failed to create order. Please try again.');
      }
    }
  );

  const updateOrderMutation = useMutation(
    (data: OrderFormData) => axios.put(`/api/orders/${id}`, data),
    {
      onSuccess: () => {
        navigate('/orders');
      },
      onError: (error: any) => {
        console.error('Error updating order:', error);
        alert('Failed to update order. Please try again.');
      }
    }
  );

  const onSubmit = (data: OrderFormData) => {
    if (isEdit) {
      updateOrderMutation.mutate(data);
    } else {
      createOrderMutation.mutate(data);
    }
  };

  return (
    <div className="max-w-4xl mx-auto">
      <h1 className="text-2xl font-bold mb-6">{isEdit ? 'Edit Order' : 'New Order'}</h1>
      
      <form onSubmit={handleSubmit(onSubmit)} className="space-y-6">
        {/* Customer Selection */}
        <div>
          <label className="block text-sm font-medium text-gray-700">Customer</label>
          <select
            {...register('customerId', { required: 'Customer is required', valueAsNumber: true })}
            className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500"
          >
            <option value="0">Select a customer</option>
            {customers?.map((customer: any) => (
              <option key={customer.id} value={customer.id}>
                {customer.name} {customer.discount_percentage > 0 ? `(${customer.discount_percentage}% discount)` : ''}
              </option>
            ))}
          </select>
          {errors.customerId && <p className="mt-1 text-sm text-red-600">{errors.customerId.message}</p>}
        </div>

        {/* Order Items */}
        <div>
          <label className="block text-sm font-medium text-gray-700">Items</label>
          {fields.map((field, index) => (
            <div key={field.id} className="flex space-x-4 mt-2 items-end">
              <div className="flex-1">
                <select
                  {...register(`items.${index}.productId`, { required: 'Product is required', valueAsNumber: true })}
                  className="block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500"
                >
                  <option value="0">Select a product</option>
                  {products?.map((product: any) => (
                    <option key={product.id} value={product.id}>
                      {product.name} (${product.price_per_lb}/lb)
                    </option>
                  ))}
                </select>
                {errors.items?.[index]?.productId && (
                  <p className="mt-1 text-sm text-red-600">{errors.items[index]?.productId?.message}</p>
                )}
              </div>
              <div className="w-32">
                <input
                  type="number"
                  step="0.01"
                  {...register(`items.${index}.quantity`, {
                    required: 'Quantity is required',
                    min: { value: 0.01, message: 'Quantity must be greater than 0' },
                    valueAsNumber: true
                  })}
                  className="block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500"
                  placeholder="Quantity (lbs)"
                />
                {errors.items?.[index]?.quantity && (
                  <p className="mt-1 text-sm text-red-600">{errors.items[index]?.quantity?.message}</p>
                )}
              </div>
              <button
                type="button"
                onClick={() => remove(index)}
                className="p-2 text-red-600 hover:text-red-800"
                disabled={fields.length === 1}
              >
                <TrashIcon className="h-5 w-5" />
              </button>
            </div>
          ))}
          <button
            type="button"
            onClick={() => append({ productId: 0, quantity: 1 })}
            className="mt-2 flex items-center text-blue-600 hover:text-blue-800"
          >
            <PlusIcon className="h-5 w-5 mr-1" /> Add Item
          </button>
        </div>

        {/* Order Summary */}
        <div className="border-t pt-4">
          <h2 className="text-lg font-medium text-gray-900">Order Summary</h2>
          <div className="mt-2 space-y-2">
            <p>Subtotal: ${orderSummary.subtotal.toFixed(2)}</p>
            <p>Discount: ${orderSummary.discount.toFixed(2)}</p>
            <p>Tax (8.75%): ${orderSummary.taxAmount.toFixed(2)}</p>
            <p className="font-bold">Total: ${orderSummary.total.toFixed(2)}</p>
          </div>
        </div>

        {/* Delivery Date */}
        <div>
          <label className="block text-sm font-medium text-gray-700">Delivery Date</label>
          <input
            type="date"
            {...register('deliveryDate')}
            className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500"
          />
        </div>

        {/* Delivery Instructions */}
        <div>
          <label className="block text-sm font-medium text-gray-700">Delivery Instructions</label>
          <textarea
            {...register('deliveryInstructions')}
            className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500"
            rows={4}
          />
        </div>

        {/* Notes */}
        <div>
          <label className="block text-sm font-medium text-gray-700">Notes</label>
          <textarea
            {...register('notes')}
            className="mt-1 block w-full rounded-md border-gray-300 shadow-sm focus:border-blue-500 focus:ring-blue-500"
            rows={4}
          />
        </div>

        {/* Submit/Cancel Buttons */}
        <div className="flex justify-end space-x-4">
          <button
            type="button"
            onClick={() => navigate('/orders')}
            className="px-4 py-2 border border-gray-300 rounded-md text-gray-700 hover:bg-gray-50"
          >
            Cancel
          </button>
          <button
            type="submit"
            disabled={createOrderMutation.isLoading || updateOrderMutation.isLoading}
            className="px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 disabled:bg-blue-300"
          >
            {isEdit ? 'Update Order' : 'Create Order'}
          </button>
        </div>
      </form>
    </div>
  );
}