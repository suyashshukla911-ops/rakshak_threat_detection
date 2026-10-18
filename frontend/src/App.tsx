import {Routes,Route} from 'react-router-dom';
import Dashboard from './pages/Dashboard';
import IncidentPage from './pages/IncidentPage';
export default function App(){return <Routes><Route path="/" element={<Dashboard/>}/><Route path="/incidents/:id" element={<IncidentPage/>}/></Routes>}
