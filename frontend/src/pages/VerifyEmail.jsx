import { useEffect, useRef } from "react";
import { useNavigate } from "react-router-dom";
import { axiosInstance } from "../lib/axios";
import toast from "react-hot-toast";

const VerifyEmail = () => {
  const navigate = useNavigate();
  const called = useRef(false); // ✅ Prevents multiple calls or toasts

  useEffect(() => {
    const token = new URLSearchParams(window.location.search).get("token");

    const verify = async () => {
      if (!token || called.current) return;
      called.current = true;

      try {
        await axiosInstance.get(`/auth/verify-email?token=${token}`);
        toast.success("Email verified! You can now log in.");
        navigate("/login");
      } catch (err) {
        toast.error(err?.response?.data?.message || "Invalid or expired token.");
        navigate("/signup");
      }
    };

    verify();
  }, [navigate]);

  return (
    <div className="flex justify-center items-center h-screen text-xl">
      Verifying your email...
    </div>
  );
};

export default VerifyEmail;
