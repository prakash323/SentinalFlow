import { Suspense, lazy } from 'react';
import { BrowserRouter, Navigate, Route, Routes, useLocation } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';

import { AuthProvider, useAuth } from './auth/AuthContext';
import RequireAuth, { postLoginTarget } from './auth/RequireAuth';
import AdminOnly from './components/AdminOnly';
import ErrorBoundary from './components/ErrorBoundary';
import { ToastProvider } from './components/feedback';
import { Loading } from './components/ui';
import { ThemeProvider } from './hooks/useTheme';
import Login from './pages/Login';

// Route-level code splitting keeps the initial bundle small; the chart library
// and each page load on first visit. The public site is its own chunk so the
// SOC never pays for it (and vice versa).
const PublicLayout = lazy(() => import('./layouts/PublicLayout'));
const Home = lazy(() => import('./pages/Home'));
const Dashboard = lazy(() => import('./pages/Dashboard'));
const Events = lazy(() => import('./pages/Events'));
const EventDetail = lazy(() => import('./pages/EventDetail'));
const CreateEvent = lazy(() => import('./pages/CreateEvent'));
const Predictions = lazy(() => import('./pages/Predictions'));
const Alerts = lazy(() => import('./pages/Alerts'));
const AlertDetail = lazy(() => import('./pages/AlertDetail'));
const Incidents = lazy(() => import('./pages/Incidents'));
const IncidentDetail = lazy(() => import('./pages/IncidentDetail'));
const Entities = lazy(() => import('./pages/Entities'));
const EntityDetail = lazy(() => import('./pages/EntityDetail'));
const Simulator = lazy(() => import('./pages/Simulator'));
const ReplayRuns = lazy(() => import('./pages/ReplayRuns'));
const ReplayDetail = lazy(() => import('./pages/ReplayDetail'));
const AuditLogs = lazy(() => import('./pages/AuditLogs'));
const System = lazy(() => import('./pages/System'));
const NotFound = lazy(() => import('./pages/NotFound'));

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 10000,
      refetchOnWindowFocus: false,
      // Client errors (4xx) will not fix themselves - only retry transient failures.
      retry: (count, error) => {
        const status = (error as { status?: number })?.status;
        return count < 2 && (status === undefined || status >= 500);
      },
    },
  },
});

// A signed-in user has nothing to do on /login: send them where they were going.
function LoginRoute() {
  const { isAuthenticated } = useAuth();
  const location = useLocation();
  if (isAuthenticated) return <Navigate to={postLoginTarget(location.state)} replace />;
  return <Login />;
}

/*
 * Route map
 *   /            public home              (PublicLayout)
 *   /login       public sign-in           (redirects to the app when already signed in)
 *   everything else is behind RequireAuth -> AppShell, so /dashboard and every
 *   existing page stay protected; unknown paths redirect to /login when signed out.
 *   Admin-only screens are additionally guarded by AdminOnly (and by the API).
 */
function AppRoutes() {
  const { pathname } = useLocation();
  return (
    <ErrorBoundary resetKey={pathname}>
      <Suspense fallback={<Loading />}>
        <Routes>
          <Route element={<PublicLayout />}>
            <Route index element={<Home />} />
          </Route>

          <Route path="login" element={<LoginRoute />} />

          <Route element={<RequireAuth />}>
            <Route path="dashboard" element={<Dashboard />} />
            <Route path="events" element={<Events />} />
            <Route path="events/new" element={<CreateEvent />} />
            <Route path="events/:eventId" element={<EventDetail />} />
            <Route path="predictions" element={<Predictions />} />
            <Route path="alerts" element={<Alerts />} />
            <Route path="alerts/:id" element={<AlertDetail />} />
            <Route path="incidents" element={<Incidents />} />
            <Route path="incidents/:id" element={<IncidentDetail />} />
            <Route path="entities" element={<Entities />} />
            <Route path="entities/:entityId" element={<EntityDetail />} />
            <Route path="simulator" element={<Simulator />} />
            <Route path="replay-runs" element={<AdminOnly what="Replay runs"><ReplayRuns /></AdminOnly>} />
            <Route path="replay-runs/:runKey" element={<AdminOnly what="Replay runs"><ReplayDetail /></AdminOnly>} />
            <Route path="audit-logs" element={<AdminOnly what="The audit log"><AuditLogs /></AdminOnly>} />
            <Route path="system" element={<System />} />
            <Route path="*" element={<NotFound />} />
          </Route>
        </Routes>
      </Suspense>
    </ErrorBoundary>
  );
}

export default function App() {
  return (
    <ThemeProvider>
      <QueryClientProvider client={queryClient}>
        <AuthProvider>
          <ToastProvider>
            <BrowserRouter>
              <AppRoutes />
            </BrowserRouter>
          </ToastProvider>
        </AuthProvider>
      </QueryClientProvider>
    </ThemeProvider>
  );
}
