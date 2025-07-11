import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { userAPI } from '../../utils/api';

const AddUser = () => {
  const navigate = useNavigate();
  const [formData, setFormData] = useState({
    firstName: '',
    middleName: '',
    lastName: '',
    employeeId: '',
    email: '',
    phoneNumber: '',
    dateOfBirth: '',
    gender: '',
    joiningDate: '',
    department: '',
    designation: '',
    employmentType: '',
    manager: '',
    workLocation: '',
    status: 'Active',
    username: '',
    password: ''
  });
  const [error, setError] = useState('');

  const handleInputChange = (e) => {
    const { name, value } = e.target;
    setFormData(prev => ({
      ...prev,
      [name]: value
    }));
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      const userData = {
        firstName: formData.firstName,
        middleName: formData.middleName,
        lastName: formData.lastName,
        employeeId: formData.employeeId,
        email: formData.email,
        phoneNumber: formData.phoneNumber,
        dateOfBirth: formData.dateOfBirth,
        gender: formData.gender,
        joiningDate: formData.joiningDate,
        department: formData.department,
        designation: formData.designation,
        employmentType: formData.employmentType,
        reportingManager: formData.manager,
        workLocation: formData.workLocation,
        isActive: formData.status === 'Active',
        username: formData.username,
        password: formData.password
      };

      await userAPI.createUser(userData);
      navigate('/admin/users');
    } catch (err) {
      setError(err.response?.data?.message || 'Failed to add user');
    }
  };

  return (
    <div className="container-fluid py-4">
      <h2>Add New User</h2>
      {error && (
        <div className="alert alert-danger" role="alert">
          {error}
        </div>
      )}
      <form onSubmit={handleSubmit}>
        <div className="row g-3">
          <div className="col-md-4">
            <label className="form-label">First Name *</label>
            <input
              type="text"
              className="form-control"
              name="firstName"
              value={formData.firstName}
              onChange={handleInputChange}
              required
            />
          </div>
          <div className="col-md-4">
            <label className="form-label">Middle Name</label>
            <input
              type="text"
              className="form-control"
              name="middleName"
              value={formData.middleName}
              onChange={handleInputChange}
            />
          </div>
          <div className="col-md-4">
            <label className="form-label">Last Name *</label>
            <input
              type="text"
              className="form-control"
              name="lastName"
              value={formData.lastName}
              onChange={handleInputChange}
              required
            />
          </div>
          <div className="col-md-6">
            <label className="form-label">Employee ID *</label>
            <input
              type="text"
              className="form-control"
              name="employeeId"
              value={formData.employeeId}
              onChange={handleInputChange}
              required
            />
          </div>
          <div className="col-md-6">
            <label className="form-label">Email Address *</label>
            <input
              type="email"
              className="form-control"
              name="email"
              value={formData.email}
              onChange={handleInputChange}
              required
            />
          </div>
          <div className="col-md-6">
            <label className="form-label">Phone Number</label>
            <input
              type="tel"
              className="form-control"
              name="phoneNumber"
              value={formData.phoneNumber}
              onChange={handleInputChange}
            />
          </div>
          <div className="col-md-6">
            <label className="form-label">Date of Birth</label>
            <input
              type="date"
              className="form-control"
              name="dateOfBirth"
              value={formData.dateOfBirth}
              onChange={handleInputChange}
            />
          </div>
          <div className="col-md-6">
            <label className="form-label">Gender</label>
            <select
              className="form-select"
              name="gender"
              value={formData.gender}
              onChange={handleInputChange}
            >
              <option value="">Select Gender</option>
              <option value="Male">Male</option>
              <option value="Female">Female</option>
              <option value="Other">Other</option>
              <option value="Prefer not to say">Prefer not to say</option>
            </select>
          </div>
          <div className="col-md-6">
            <label className="form-label">Joining Date</label>
            <input
              type="date"
              className="form-control"
              name="joiningDate"
              value={formData.joiningDate}
              onChange={handleInputChange}
            />
          </div>
          <div className="col-md-6">
            <label className="form-label">Department</label>
            <input
              type="text"
              className="form-control"
              name="department"
              value={formData.department}
              onChange={handleInputChange}
            />
          </div>
          <div className="col-md-6">
            <label className="form-label">Designation / Job Title</label>
            <input
              type="text"
              className="form-control"
              name="designation"
              value={formData.designation}
              onChange={handleInputChange}
            />
          </div>
          <div className="col-md-6">
            <label className="form-label">Employment Type</label>
            <select
              className="form-select"
              name="employmentType"
              value={formData.employmentType}
              onChange={handleInputChange}
            >
              <option value="">Select Employment Type</option>
              <option value="Full-time">Full-time</option>
              <option value="Part-time">Part-time</option>
              <option value="Contract">Contract</option>
              <option value="Internship">Internship</option>
            </select>
          </div>
          <div className="col-md-6">
            <label className="form-label">Manager / Supervisor</label>
            <input
              type="text"
              className="form-control"
              name="manager"
              value={formData.manager}
              onChange={handleInputChange}
            />
          </div>
          <div className="col-md-6">
            <label className="form-label">Work Location</label>
            <input
              type="text"
              className="form-control"
              name="workLocation"
              value={formData.workLocation}
              onChange={handleInputChange}
            />
          </div>
          <div className="col-md-6">
            <label className="form-label">Status</label>
            <select
              className="form-select"
              name="status"
              value={formData.status}
              onChange={handleInputChange}
            >
              <option value="Active">Active</option>
              <option value="Inactive">Inactive</option>
              <option value="On leave">On leave</option>
            </select>
          </div>
          <div className="col-md-6">
            <label className="form-label">Username *</label>
            <input
              type="text"
              className="form-control"
              name="username"
              value={formData.username}
              onChange={handleInputChange}
              required
            />
          </div>
          <div className="col-md-6">
            <label className="form-label">Password *</label>
            <input
              type="password"
              className="form-control"
              name="password"
              value={formData.password}
              onChange={handleInputChange}
              required
            />
          </div>
        </div>
        <div className="mt-4">
          <button type="submit" className="btn btn-primary">Add User</button>
          <button type="button" className="btn btn-secondary ms-2" onClick={() => navigate('/admin/users')}>Cancel</button>
        </div>
      </form>
    </div>
  );
};

export default AddUser;
