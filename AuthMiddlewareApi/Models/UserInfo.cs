namespace JinnHoward.AuthMiddlewareApi.Models
{
    public record UserInfo
    {
        public Guid UserId { get; set; }
        public string Email { get; set; } = string.Empty;
        public string FirstName { get; set; } = string.Empty;
        public string LastName { get; set; } = string.Empty;
        public Guid CompanyId { get; set; }
        public Guid DepartmentId { get; set; }
    }
}
