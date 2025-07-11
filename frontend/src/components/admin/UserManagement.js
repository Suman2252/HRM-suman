import React, { useState, useEffect } from 'react';
import { useAuth } from '../../context/AuthContext';
import { userAPI } from '../../utils/api';

const UserManagement = () => {
  const { user } = useAuth();
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [searchTerm, setSearchTerm] = useState('');
  const [roleFilter, setRoleFilter] = useState('');
  const [departmentFilter, setDepartmentFilter] = useState('');
  const [currentPage, setCurrentPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const [totalUsers, setTotalUsers] = useState(0);

  const [showAddModal, setShowAddModal] = useState(false);
  const [addFormData, setAddFormData] = useState({
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

  useEffect(() => {
    fetchUsers();
  }, [currentPage, searchTerm, roleFilter, departmentFilter]);

  const fetchUsers = async () => {
    try {
      setLoading(true);
      const params = {
        page: currentPage,
        limit: 10,
        search: searchTerm,
        role: roleFilter,
        department: departmentFilter
      };

      const response = await userAPI.getAllUsers(params);
      setUsers(response.data.users);
      setTotalPages(response.data.totalPages);
      setTotalUsers(response.data.total);
    } catch (err) {
      setError(err.response?.data?.message || 'Failed to fetch users');
    } finally {
      setLoading(false);
    }
  };

  const handleSearch = (e) => {
    setSearchTerm(e.target.value);
    setCurrentPage(1);
  };

  const handleRoleFilter = (e) => {
    setRoleFilter(e.target.value);
    setCurrentPage(1);
  };

  const handleDepartmentFilter = (e) => {
    setDepartmentFilter(e.target.value);
    setCurrentPage(1);
  };

  const resetFilters = () => {
    setSearchTerm('');
    setRoleFilter('');
    setDepartmentFilter('');
    setCurrentPage(1);
  };

  const formatDate = (date) => {
    if (!date) return 'Not provided';
    return new Date(date).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric'
    });
  };

  const getRoleBadgeColor = (role) => {
    const colors = {
      'Admin': 'bg-danger',
      'Vice President': 'bg-primary',
      'HR BP': 'bg-info',
      'HR Manager': 'bg-info',
      'HR Executive': 'bg-info',
      'Team Manager': 'bg-warning',
      'Team Leader': 'bg-warning',
      'Employee': 'bg-secondary'
    };
    return colors[role] || 'bg-secondary';
  };

  const handleAddInputChange = (e) => {
    const { name, value } = e.target;
    setAddFormData(prev => ({
      ...prev,
      [name]: value
    }));
  };

  const handleAddUser = async (e) => {
    e.preventDefault();
    try {
      // Prepare user data for API
      const userData = {
        firstName: addFormData.firstName,
        middleName: addFormData.middleName,
        lastName: addFormData.lastName,
        employeeId: addFormData.employeeId,
        email: addFormData.email,
        phoneNumber: addFormData.phoneNumber,
        dateOfBirth: addFormData.dateOfBirth,
        gender: addFormData.gender,
        joiningDate: addFormData.joiningDate,
        department: addFormData.department,
        designation: addFormData.designation,
        employmentType: addFormData.employmentType,
        reportingManager: addFormData.manager,
        workLocation: addFormData.workLocation,
        isActive: addFormData.status === 'Active',
        username: addFormData.username,
        password: addFormData.password
      };

      await userAPI.createUser(userData);
      setShowAddModal(false);
      setAddFormData({
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
      fetchUsers();
      setError('');
    } catch (err) {
      setError(err.response?.data?.message || 'Failed to add user');
    }
  };

  if (loading && users.length === 0) {
    return (
      <div className="d-flex justify-content-center align-items-center" style={{ height: '400px' }}>
        <div className="spinner-border text-primary" role="status">
          <span className="visually-hidden">Loading...</span>
        </div>
      </div>
    );
  }

  return (
    <div className="container-fluid">
      {/* Page Header */}
      <div className="d-flex justify-content-between align-items-center mb-4">
        <div>
          <h2 className="mb-1">User Management</h2>
          <p className="text-muted">Manage all users and their information</p>
        </div>
        <div className="d-flex gap-2">
          <span className="badge bg-primary fs-6">{totalUsers} Total Users</span>
          <button className="btn btn-primary" onClick={() => setShowAddModal(true)}>
            <i className="bi bi-plus-circle me-1"></i> Add User
          </button>
        </div>
      </div>

      {/* Filters */}
      <div className="card mb-4">
        <div className="card-body">
          <div className="row g-3">
            <div className="col-md-4">
              <label className="form-label">Search Users</label>
              <div className="input-group">
                <span className="input-group-text">
                  <i className="bi bi-search"></i>
                </span>
                <input
                  type="text"
                  className="form-control"
                  placeholder="Search by name, email, or employee ID..."
                  value={searchTerm}
                  onChange={handleSearch}
                />
              </div>
            </div>
            <div className="col-md-3">
              <label className="form-label">Filter by Role</label>
              <select
                className="form-select"
                value={roleFilter}
                onChange={handleRoleFilter}
              >
                <option value="">All Roles</option>
                <option value="Admin">Admin</option>
                <option value="Vice President">Vice President</option>
                <option value="HR BP">HR BP</option>
                <option value="HR Manager">HR Manager</option>
                <option value="HR Executive">HR Executive</option>
                <option value="Team Manager">Team Manager</option>
                <option value="Team Leader">Team Leader</option>
                <option value="Employee">Employee</option>
              </select>
            </div>
            <div className="col-md-3">
              <label className="form-label">Filter by Department</label>
              <select
                className="form-select"
                value={departmentFilter}
                onChange={handleDepartmentFilter}
              >
                <option value="">All Departments</option>
                <option value="Management">Management</option>
                <option value="Human Resources">Human Resources</option>
                <option value="Engineering">Engineering</option>
                <option value="Operations">Operations</option>
              </select>
            </div>
            <div className="col-md-2">
              <label className="form-label">&nbsp;</label>
              <button 
                className="btn btn-outline-secondary w-100"
                onClick={resetFilters}
              >
                <i className="bi bi-arrow-clockwise me-1"></i>
                Reset
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Error Alert */}
      {error && (
        <div className="alert alert-danger alert-dismissible fade show" role="alert">
          {error}
          <button 
            type="button" 
            className="btn-close" 
            onClick={() => setError('')}
          ></button>
        </div>
      )}

      {/* Users Table */}
      <div className="card">
        <div className="card-body">
          {loading ? (
            <div className="text-center py-4">
              <div className="spinner-border text-primary" role="status">
                <span className="visually-hidden">Loading...</span>
              </div>
            </div>
          ) : users.length === 0 ? (
            <div className="text-center py-5">
              <i className="bi bi-people text-muted" style={{ fontSize: '3rem' }}></i>
              <h5 className="mt-3 text-muted">No users found</h5>
              <p className="text-muted">Try adjusting your search criteria</p>
            </div>
          ) : (
            <>
              <div className="table-responsive">
                <table className="table table-hover">
                  <thead className="table-light">
                    <tr>
                      <th>Employee</th>
                      <th>Role</th>
                      <th>Department</th>
                      <th>Employee ID</th>
                      <th>Contact</th>
                      <th>Joining Date</th>
                      <th>Status</th>
                      <th>Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {users.map((userData) => (
                      <tr key={userData._id}>
                        <td>
                          <div className="d-flex align-items-center">
                            <div className="bg-primary rounded-circle d-flex align-items-center justify-content-center me-3"
                                 style={{ width: '40px', height: '40px' }}>
                              <i className="bi bi-person text-white"></i>
                            </div>
                            <div>
                              <div className="fw-semibold">{userData.firstName} {userData.lastName}</div>
                              <small className="text-muted">{userData.email}</small>
                            </div>
                          </div>
                        </td>
                        <td>
                          <span className={`badge ${getRoleBadgeColor(userData.role)}`}>
                            {userData.role}
                          </span>
                        </td>
                        <td>
                          {userData.department?.name || userData.department || 'Not assigned'}
                        </td>
                        <td>
                          <code>{userData.employeeId || 'Not assigned'}</code>
                        </td>
                        <td>
                          <div>
                            <small className="d-block">{userData.phoneNumber || 'Not provided'}</small>
                          </div>
                        </td>
                        <td>
                          {formatDate(userData.joiningDate)}
                        </td>
                        <td>
                          <span className={`badge ${userData.isActive ? 'bg-success' : 'bg-danger'}`}>
                            {userData.isActive ? 'Active' : 'Inactive'}
                          </span>
                        </td>
                        <td>
                          <div className="btn-group" role="group">
                            <button
                              className="btn btn-sm btn-outline-primary"
                              title="View Profile"
                            >
                              <i className="bi bi-eye"></i>
                            </button>
                            {(user?.role === 'Admin' || user?.role === 'Vice President' || user?.role === 'HR Manager') && (
                              <button
                                className="btn btn-sm btn-outline-secondary"
                                title="Edit User"
                              >
                                <i className="bi bi-pencil"></i>
                              </button>
                            )}
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              {/* Pagination */}
              {totalPages > 1 && (
                <nav className="mt-4">
                  <ul className="pagination justify-content-center">
                    <li className={`page-item ${currentPage === 1 ? 'disabled' : ''}`}>
                      <button 
                        className="page-link"
                        onClick={() => setCurrentPage(currentPage - 1)}
                        disabled={currentPage === 1}
                      >
                        Previous
                      </button>
                    </li>
                    {[...Array(totalPages)].map((_, index) => (
                      <li key={index} className={`page-item ${currentPage === index + 1 ? 'active' : ''}`}>
                        <button 
                          className="page-link"
                          onClick={() => setCurrentPage(index + 1)}
                        >
                          {index + 1}
                        </button>
                      </li>
                    ))}
                    <li className={`page-item ${currentPage === totalPages ? 'disabled' : ''}`}>
                      <button 
                        className="page-link"
                        onClick={() => setCurrentPage(currentPage + 1)}
                        disabled={currentPage === totalPages}
                      >
                        Next
                      </button>
                    </li>
                  </ul>
                </nav>
              )}
            </>
          )}
        </div>
      </div>

      {/* Add User Modal */}
      {showAddModal && (
        <div className="modal show d-block" tabIndex="-1" style={{ backgroundColor: 'rgba(0,0,0,0.5)' }}>
          <div className="modal-dialog modal-lg">
            <div className="modal-content">
              <form onSubmit={handleAddUser}>
                <div className="modal-header">
                  <h5 className="modal-title">Add New User</h5>
                  <button 
                    type="button" 
                    className="btn-close"
                    onClick={() => setShowAddModal(false)}
                  ></button>
                </div>
                <div className="modal-body">
                  <div className="row g-3">
                    <div className="col-md-4">
                      <label className="form-label">First Name *</label>
                      <input
                        type="text"
                        className="form-control"
                        name="firstName"
                        value={addFormData.firstName}
                        onChange={handleAddInputChange}
                        required
                      />
                    </div>
                    <div className="col-md-4">
                      <label className="form-label">Middle Name</label>
                      <input
                        type="text"
                        className="form-control"
                        name="middleName"
                        value={addFormData.middleName}
                        onChange={handleAddInputChange}
                      />
                    </div>
                    <div className="col-md-4">
                      <label className="form-label">Last Name *</label>
                      <input
                        type="text"
                        className="form-control"
                        name="lastName"
                        value={addFormData.lastName}
                        onChange={handleAddInputChange}
                        required
                      />
                    </div>
                    <div className="col-md-6">
                      <label className="form-label">Employee ID *</label>
                      <input
                        type="text"
                        className="form-control"
                        name="employeeId"
                        value={addFormData.employeeId}
                        onChange={handleAddInputChange}
                        required
                      />
                    </div>
                    <div className="col-md-6">
                      <label className="form-label">Email Address *</label>
                      <input
                        type="email"
                        className="form-control"
                        name="email"
                        value={addFormData.email}
                        onChange={handleAddInputChange}
                        required
                      />
                    </div>
                    <div className="col-md-6">
                      <label className="form-label">Phone Number</label>
                      <input
                        type="tel"
                        className="form-control"
                        name="phoneNumber"
                        value={addFormData.phoneNumber}
                        onChange={handleAddInputChange}
                      />
                    </div>
                    <div className="col-md-6">
                      <label className="form-label">Date of Birth</label>
                      <input
                        type="date"
                        className="form-control"
                        name="dateOfBirth"
                        value={addFormData.dateOfBirth}
                        onChange={handleAddInputChange}
                      />
                    </div>
                    <div className="col-md-6">
                      <label className="form-label">Gender</label>
                      <select
                        className="form-select"
                        name="gender"
                        value={addFormData.gender}
                        onChange={handleAddInputChange}
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
                        value={addFormData.joiningDate}
                        onChange={handleAddInputChange}
                      />
                    </div>
                    <div className="col-md-6">
                      <label className="form-label">Department</label>
                      <input
                        type="text"
                        className="form-control"
                        name="department"
                        value={addFormData.department}
                        onChange={handleAddInputChange}
                      />
                    </div>
                    <div className="col-md-6">
                      <label className="form-label">Designation / Job Title</label>
                      <input
                        type="text"
                        className="form-control"
                        name="designation"
                        value={addFormData.designation}
                        onChange={handleAddInputChange}
                      />
                    </div>
                    <div className="col-md-6">
                      <label className="form-label">Employment Type</label>
                      <select
                        className="form-select"
                        name="employmentType"
                        value={addFormData.employmentType}
                        onChange={handleAddInputChange}
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
                        value={addFormData.manager}
                        onChange={handleAddInputChange}
                      />
                    </div>
                    <div className="col-md-6">
                      <label className="form-label">Work Location</label>
                      <input
                        type="text"
                        className="form-control"
                        name="workLocation"
                        value={addFormData.workLocation}
                        onChange={handleAddInputChange}
                      />
                    </div>
                    <div className="col-md-6">
                      <label className="form-label">Status</label>
                      <select
                        className="form-select"
                        name="status"
                        value={addFormData.status}
                        onChange={handleAddInputChange}
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
                        value={addFormData.username}
                        onChange={handleAddInputChange}
                        required
                      />
                    </div>
                    <div className="col-md-6">
                      <label className="form-label">Password *</label>
                      <input
                        type="password"
                        className="form-control"
                        name="password"
                        value={addFormData.password}
                        onChange={handleAddInputChange}
                        required
                      />
                    </div>
                  </div>
                </div>
                <div className="modal-footer">
                  <button 
                    type="button" 
                    className="btn btn-secondary"
                    onClick={() => setShowAddModal(false)}
                  >
                    Cancel
                  </button>
                  <button type="submit" className="btn btn-primary">
                    Add User
                  </button>
                </div>
              </form>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default UserManagement;
