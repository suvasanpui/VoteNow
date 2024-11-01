import logo from "./logo.svg";
import "./App.css";
import { Navigate, Route, Routes } from "react-router-dom";
import Login from "./pages/Login";
import Signup from "./pages/Signup";
import Home from "./pages/Home";
import { useState } from "react";
import RefreshHandler from "./RefreshHandler";
import { ToastContainer} from "react-toastify";
import 'react-toastify/dist/ReactToastify.css';

function App() {
  const [isAuthenticate, setIsauthenticate] = useState(false);

  const PrivateRoute = ({ element }) => {
    return isAuthenticate ? element : <Navigate to="/login" />;
  };

  return (
    <div className="App">
      <ToastContainer/>
      <RefreshHandler setIsauthenticate={setIsauthenticate} />
      <Routes>
        <Route path="/" element={<Navigate to="/Login" />} />
        <Route path="/login" element={<Login />} />
        <Route path="/signup" element={<Signup />} />
        <Route path="/home" element={<PrivateRoute element={<Home />} />} />
      </Routes>
    </div>
  );
}

export default App;
