import React, { useEffect } from "react";
import { useLocation, useNavigate } from "react-router-dom";

function RefreshHandler({ setIsauthenticate }) {
  const location = useLocation();
  const navigate = useNavigate();

  useEffect(() => {
    if (localStorage.getItem("loggedToken")) {
      setIsauthenticate(true);
      if (
        location.pathname === "/" ||
        location.pathname === "/login" ||
        location.pathname === "/signup"
      ) {
        navigate("/home", { replace: false });
      }
    }
  }, [location, setIsauthenticate, navigate]);
  return null;
}

export default RefreshHandler;
