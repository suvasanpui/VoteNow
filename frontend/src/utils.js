import { ToastContainer ,toast} from "react-toastify";

export const handleSuccess = (message) => {
  toast.success(message, {
    position: "top-right",
    autoClose:5000,
    hideProgressBar:true,
    closeOnClick:true,
    pauseOnHover:true,
    draggable:true,
  });
};

export const handleError = (message) => {
  toast.error(message, {
    position: "top-right",
  });
};
