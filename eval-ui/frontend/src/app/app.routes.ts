import { Routes } from '@angular/router';

export const routes: Routes = [
  {
    path: '',
    loadComponent: () => import('./pages/dashboard/dashboard.component').then(m => m.DashboardComponent),
  },
  {
    path: 'runs',
    loadComponent: () => import('./pages/runs-list/runs-list.component').then(m => m.RunsListComponent),
  },
  {
    path: 'runs/:id',
    loadComponent: () => import('./pages/run-detail/run-detail.component').then(m => m.RunDetailComponent),
  },
  {
    path: 'playground',
    loadComponent: () => import('./pages/playground/playground.component').then(m => m.PlaygroundComponent),
  },
  { path: '**', redirectTo: '' },
];
