import { useState } from 'react';
import './App.css';

function App() {
  const [isLoginVisible, setIsLoginVisible] = useState(false);
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [message, setMessage] = useState('');

  const handleLogin = async (e) => {
    e.preventDefault();
    try {
      const response = await fetch('http://127.0.0.1:8000/token', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({
          username: username,
          password: password,
        }),
        credentials: 'include', 
      });

      if (response.ok) {
        const result = await response.json();
        localStorage.setItem('token', result.access_token);
        setMessage('Login successful');
        setIsLoginVisible(false);
      } else {
        const errorData = await response.json();
        setMessage(`Login failed: ${errorData.detail || 'Unknown error'}`);
      }
    } catch (error) {
      setMessage(`An error occurred: ${error.message}`);
    }
  };

  const handleLogout = async () => {
    try {
      const response = await fetch('http://127.0.0.1:8000/logout', {
        method: 'POST',
        credentials: 'include', 
      });
  
      if (response.ok) {
        localStorage.removeItem('token');
        setMessage('Logout successful');
      } else {
        const errorData = await response.json();
        setMessage(`Logout failed: ${errorData.detail || 'Unknown error'}`);
      }
    } catch (error) {
      setMessage(`Logout failed: ${error.message}`);
    }
  }
  
  return (
    <div className="App flex flex-col items-center justify-center min-h-screen bg-gray-100 p-4">
      <h1 className="text-2xl font-bold mb-6">User Authentication</h1>

      {!isLoginVisible ? (
        <button
          onClick={() => setIsLoginVisible(true)}
          className="bg-blue-500 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded focus:outline-none focus:shadow-outline mb-4"
        >
          Login
        </button>
      ) : (
        <form onSubmit={handleLogin} className="bg-white shadow-md rounded px-8 pt-6 pb-8 mb-4 w-full max-w-sm">
          <div className="mb-4">
            <label className="block text-gray-700 text-sm font-bold mb-2" htmlFor="username">
              Username:
            </label>
            <input
              type="text"
              id="username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              required
              autoComplete="username"
              className="shadow appearance-none border rounded w-full py-2 px-3 text-gray-700 leading-tight focus:outline-none focus:shadow-outline"
            />
          </div>
          <div className="mb-6">
            <label className="block text-gray-700 text-sm font-bold mb-2" htmlFor="password">
              Password:
            </label>
            <input
              type="password"
              id="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              autoComplete="current-password"
              className="shadow appearance-none border rounded w-full py-2 px-3 text-gray-700 mb-3 leading-tight focus:outline-none focus:shadow-outline"
            />
          </div>
          <button
            type="submit"
            className="bg-blue-500 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded focus:outline-none focus:shadow-outline"
          >
            Submit
          </button>
        </form>
      )}

      <h2 className="text-xl font-semibold mb-4">Message: {message}</h2>

      <button
        onClick={handleLogout}
        className="bg-red-500 hover:bg-red-700 text-white font-bold py-2 px-4 rounded focus:outline-none focus:shadow-outline"
      >
        Logout
      </button>
    </div>
  );
}

export default App;
