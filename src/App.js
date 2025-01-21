import React, { useState, useEffect, useRef } from 'react';
import { FaPlus, FaPaperPlane, FaMicrophone } from 'react-icons/fa';
import './App.css';

function App() {
  const [showLogin, setShowLogin] = useState(true);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [query, setQuery] = useState('');
  const [messages, setMessages] = useState([]);
  const [isTyping, setIsTyping] = useState(false);
  const [darkMode, setDarkMode] = useState(() => JSON.parse(localStorage.getItem('darkMode')) || false);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [showProfile, setShowProfile] = useState(false);
  const [gender, setGender] = useState('');
  const [isAdmin, setIsAdmin] = useState(false);
  const chatEndRef = useRef(null);
  const [ocrFile, setOcrFile] = useState(null);

  // Speech recognition states
  const [isListening, setIsListening] = useState(false);
  const recognitionRef = useRef(null);

  useEffect(() => {
    const accessToken = localStorage.getItem('access_token');
    const refreshToken = localStorage.getItem('refresh_token');
    if (accessToken && refreshToken) {
      setShowLogin(false);
      const storedEmail = localStorage.getItem('user_email');
      const storedGender = localStorage.getItem('user_gender');
      const storedIsAdmin = localStorage.getItem('is_admin') === 'true';
      if (storedEmail) setEmail(storedEmail);
      if (storedGender) setGender(storedGender);
      setIsAdmin(storedIsAdmin);
    }
  }, []);

  useEffect(() => {
    scrollToBottom();
  }, [messages]);

  const scrollToBottom = () => {
    chatEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  // Initialize Speech Recognition
  useEffect(() => {
    window.SpeechRecognition = window.SpeechRecognition || window.webkitSpeechRecognition;

    if ('SpeechRecognition' in window) {
      const recognition = new window.SpeechRecognition();
      recognition.continuous = false;
      recognition.lang = 'en-US';
      recognition.interimResults = false;

      recognition.onstart = () => {
        setIsListening(true);
      };

      recognition.onresult = (event) => {
        const transcript = event.results[0][0].transcript;
        // Automatically send the message upon receiving the result
        sendMessage(null, transcript);
      };

      recognition.onend = () => {
        setIsListening(false);
      };

      recognition.onerror = (event) => {
        console.error('Speech recognition error:', event.error);
        setIsListening(false);
      };

      recognitionRef.current = recognition;
    } else {
      console.warn('Speech Recognition API not supported in this browser.');
    }
  }, []);

  const handleListen = () => {
    if (recognitionRef.current) {
      if (!isListening) {
        recognitionRef.current.start();
      } else {
        recognitionRef.current.stop();
      }
    } else {
      alert('Speech Recognition API not supported in this browser.');
    }
  };

  const sendMessage = async (e, message = '') => {
    if (e && e.preventDefault) e.preventDefault();

    const currentQuery = message || query;

    if (!currentQuery && !ocrFile) {
      return;
    }

    const userMessage = { text: currentQuery || 'Sent an image.', type: 'user', time: new Date().toLocaleTimeString() };
    setMessages((prevMessages) => [...prevMessages, userMessage]);
    setQuery('');

    setIsTyping(true);
    let accessToken = localStorage.getItem('access_token');

    try {
      const tokenStatusRes = await fetch('http://127.0.0.1:5000/token-status', {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${accessToken}`,
        },
      });

      if (tokenStatusRes.status === 401) {
        accessToken = await handleTokenRefresh();
      }

      const formData = new FormData();
      formData.append('query', currentQuery);

      if (ocrFile) {
        formData.append('image', ocrFile);
      }

      const res = await fetch('http://127.0.0.1:5000/query', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${accessToken}`,
          // Do not set 'Content-Type' header when sending FormData
        },
        body: formData,
      });

      const data = await res.json();
      setIsTyping(false);

      if (res.ok) {
        const botMessage = { text: data.response, type: 'bot', time: new Date().toLocaleTimeString() };
        setMessages((prevMessages) => [...prevMessages, botMessage]);
      } else {
        setError(data.error || 'An error occurred while processing your request.');
      }

      // Clear the image after sending
      setOcrFile(null);
    } catch (err) {
      console.error('Error during sendMessage:', err);
      setError('An unexpected error occurred. Please try again.');
      setIsTyping(false);
    }
  };

  const clearChat = () => {
    setMessages([]);
  };

  const handleTokenRefresh = async () => {
    const refreshToken = localStorage.getItem('refresh_token');
    try {
      const res = await fetch('http://127.0.0.1:5000/refresh', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${refreshToken}`,
          'Content-Type': 'application/json',
        },
      });

      if (res.ok) {
        const data = await res.json();
        localStorage.setItem('access_token', data.access_token);
        return data.access_token;
      } else {
        logout();
      }
    } catch (err) {
      console.error('Error during token refresh:', err);
      logout();
    }
  };

  const login = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    try {
      const res = await fetch('http://127.0.0.1:5000/login', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ email, password }),
      });

      const data = await res.json();

      if (res.ok && data && data.user_data && data.user_data.email) {
        localStorage.setItem('access_token', data.access_token);
        localStorage.setItem('refresh_token', data.refresh_token);
        localStorage.setItem('user_email', data.user_data.email);
        localStorage.setItem('user_gender', data.user_data.gender);
        localStorage.setItem('is_admin', data.user_data.is_admin);

        setEmail(data.user_data.email);
        setGender(data.user_data.gender);
        setIsAdmin(data.user_data.is_admin);

        clearChat();
        setShowLogin(false);
      } else {
        setError('Invalid email or password!');
      }
    } catch (error) {
      console.error('Error during login:', error);
      setError('An error occurred while trying to log in. Please try again later.');
    }

    setLoading(false);
  };

  const logout = () => {
    localStorage.removeItem('access_token');
    localStorage.removeItem('refresh_token');
    localStorage.removeItem('user_email');
    localStorage.removeItem('user_gender');
    localStorage.removeItem('is_admin');
    setShowLogin(true);
    clearChat();
  };

  const toggleProfile = () => {
    setShowProfile(!showProfile);
  };

  // Define paths to local images for male and female avatars
  const maleAvatarUrl = `${process.env.PUBLIC_URL}/MEN.png`;
  const femaleAvatarUrl = `${process.env.PUBLIC_URL}/WOMAN.png`;

  // Normalize the gender value
  const normalizedGender = gender ? gender.trim().toLowerCase() : '';
  const profileAvatar = normalizedGender === 'male' ? maleAvatarUrl : femaleAvatarUrl;

  return (
    <div className={`App ${darkMode ? 'dark-mode' : ''}`}>
      {showLogin ? (
        <div className="login-container">
          <h2>Login</h2>
          <form onSubmit={login}>
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="Email"
              required
            />
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Password"
              required
            />
            {error && <div className="error">{error}</div>}
            {loading ? (
              <div className="loading">Logging in...</div>
            ) : (
              <button type="submit">Login</button>
            )}
          </form>
        </div>
      ) : (
        <div className="chat-box">
          {/* Header Ribbon with Avatar to the left of "Easychat" */}
          <div className="chat-header">
            <div className="header-content">
              <img
                src={profileAvatar}
                alt="Profile"
                className="profile-pic"
                onClick={toggleProfile}
              />
              <span className="header-title">Easychat</span>
            </div>
            {showProfile && (
              <div className="profile-popup">
                <p>Email: {email}</p>
                <button onClick={logout}>Logout</button>
              </div>
            )}
          </div>

          {/* Image Preview Pop-up */}
          {ocrFile && (
            <div className="image-preview-popup">
              <img src={URL.createObjectURL(ocrFile)} alt="Uploaded" />
              <button className="close-button" onClick={() => setOcrFile(null)}>×</button>
            </div>
          )}

          <div className="chat-area">
            {messages.map((msg, index) => (
              <div key={index} className={`message ${msg.type}`}>
                <p>{msg.text}</p>
                <span className="timestamp">{msg.time}</span>
              </div>
            ))}
            {isTyping && <div className="message bot typing"><p>...</p></div>}
            <div ref={chatEndRef} />
          </div>

          <div className="input-area-container">
            <form onSubmit={sendMessage} className="input-area">
              <FaMicrophone
                className={`microphone-icon ${isListening ? 'recording' : ''}`}
                onClick={handleListen}
              />

              <FaPlus
                className="attachment-icon"
                onClick={() => document.getElementById('file-input').click()}
              />
              <input
                type="file"
                id="file-input"
                style={{ display: 'none' }}
                accept="image/*"
                onChange={(e) => setOcrFile(e.target.files[0])}
              />

              <div className="input-wrapper">
                <input
                  type="text"
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                  placeholder="Type your message..."
                />
                <button type="submit" className="send-button">
                  <FaPaperPlane className="green-icon" />
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}

export default App;

