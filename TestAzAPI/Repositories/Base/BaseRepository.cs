using Microsoft.EntityFrameworkCore;
using System.Linq.Expressions;
using TestAzAPI.Data;

namespace TestAzAPI.Repositories.Base;

public class BaseRepository<T> : IBaseRepository<T> where T : class
{
    protected readonly TestAzDbContext _context;
    protected readonly DbSet<T> _dbSet;

    public BaseRepository(TestAzDbContext context)
    {
        _context = context;
        _dbSet = context.Set<T>();
    }

    public virtual async Task<IEnumerable<T>> GetAllAsync()
    {
        return await _dbSet.ToListAsync();
    }

    public virtual async Task<T?> GetByIdAsync(Guid id)
    {
        return await _dbSet.FindAsync(id);
    }

    public virtual async Task AddAsync(T entity)
    {
        await _dbSet.AddAsync(entity);
    }

    public virtual void Update(T entity)
    {
        _dbSet.Update(entity);
    }

    public virtual void Delete(T entity)
    {
        _dbSet.Remove(entity);
    }

    public virtual async Task SaveAsync()
    {
        await _context.SaveChangesAsync();
    }

    public virtual async Task<IEnumerable<T>> FindAsync(Expression<Func<T, bool>> predicate)
    {
        return await _dbSet.Where(predicate).ToListAsync();
    }
} 