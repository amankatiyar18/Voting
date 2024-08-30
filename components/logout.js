// src/components/UserProfile.js
import React, { useEffect, useState } from 'react';
import { getCurrentUser, logout } from '../services/api';

const UserProfile = () => {
  const [user, setUser] = useState(null);

  useEffect(() => {
    const fetchUser = async () => {
      try {
        const response = await getCurrentUser();
        setUser(response.user);
      } catch (error) {
        console.log(error);
      }
    };
    fetchUser();
  }, []);

  const handleLogout = async () => {
    try {
      await logout();
      setUser(null);
    } catch (error) {
      console.log(error);
    }
  };

  return (
    <div>
      {user ? (
        <div>
          <h2>Welcome, {user.username}</h2>
          <button onClick={handleLogout}>Logout</button>
        </div>
      ) : (
        <p>Please log in.</p>
      )}
    </div>
  );
};

export default UserProfile;
