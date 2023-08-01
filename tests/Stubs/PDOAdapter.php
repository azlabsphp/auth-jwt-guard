<?php

declare(strict_types=1);

/*
 * This file is part of the drewlabs namespace.
 *
 * (c) Sidoine Azandrew <azandrewdevelopper@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Drewlabs\Auth\JwtGuard\Tests;

use PDO;

/**
 * @mixin \PDO
 */
class PDOAdapter
{
    /**
     * @var string
     */
    private $table;

    /**
     * @var \PDO
     */
    private $pdo;

    /**
     * Creates PDO adapter instance.
     *
     * @param string|\PDO $dsn
     */
    public function __construct($dsn, array $options = [])
    {
        $options = \is_array($options) ? $options : [];
        $this->pdo = $dsn instanceof \PDO ? $dsn : new \PDO($dsn, $options['user'] ?? null, $options['password'] ?? null, $options);
    }

    public function __destruct()
    {
        unset($this->pdo);
    }

    /**
     * Proxy method call to pdo instance.
     *
     * @param mixed $name
     * @param mixed $arguments
     *
     * @return mixed
     */
    public function __call($name, $arguments)
    {
        return \call_user_func_array([$this->getPdo(), $name], $arguments);
    }

    /**
     * Set the table to work with.
     *
     * @return $this
     */
    public function table(string $table)
    {
        $this->table = $table;

        return $this;
    }

    public function select(array $conditions = [], array $columns = ['*'])
    {
        $bindings = [];
        $stmt = $this->prepareStatement(sprintf('SELECT %s FROM %s %s', implode(', ', $columns), $this->table, $this->buildConditionQuery($conditions, $bindings)));
        // Bind PDO param
        foreach ($bindings as $key => $value) {
            $stmt->bindParam($key, ...$value);
        }
        // Execute the PDO statement
        $stmt->execute();
        // Select the first matching row
        while (false !== ($result = $stmt->fetch(\PDO::FETCH_OBJ))) {
            yield $result;
        }
    }

    public function selectOne(array $conditions = [], array $columns = ['*'])
    {
        $bindings = [];
        $stmt = $this->prepareStatement(sprintf('SELECT %s FROM %s %s', implode(', ', $columns), $this->table, $this->buildConditionQuery($conditions, $bindings)));
        // Bind PDO param
        foreach ($bindings as $key => $value) {
            $stmt->bindParam($key, ...$value);
        }
        // Execute the PDO statement
        $stmt->execute();

        // Select the first matching row
        return $stmt->fetch(\PDO::FETCH_OBJ);
    }

    public function update(array $conditions, array $values = [])
    {
        $bindings = [];
        $updateBindings = [];

        $stmt = $this->prepareStatement(sprintf('UPDATE %s SET %s %s', $this->table, $this->buildUpdateQueryString($values, $updateBindings), $this->buildConditionQuery($conditions, $bindings)));

        // Bind PDO params
        foreach ($bindings as $key => $value) {
            $stmt->bindParam($key, ...$value);
        }

        // Bind PDO update params
        foreach ($updateBindings as $key => $value) {
            $stmt->bindParam($key, ...$value);
        }
        // Execute the PDO statement
        $stmt->execute();

        return $stmt->rowCount();
    }

    public function delete(array $conditions)
    {
        $bindings = [];
        $stmt = $this->prepareStatement(sprintf('DELETE FROM %s %s', $this->table, $this->buildConditionQuery($conditions, $bindings)));
        foreach ($bindings as $key => $value) {
            $stmt->bindParam($key, ...$value);
        }

        // Execute the PDO statement
        $stmt->execute();

        return $stmt->rowCount();
    }

    public function create(array $values)
    {
        $bindings = [];
        $stmt = $this->prepareStatement(sprintf('INSERT INTO %s(%s) VALUES (%s)', $this->table, implode(', ', array_keys($values)), $this->prepareCreateQuery($values, $bindings)));
        // Bind PDO params
        foreach ($bindings as $key => $value) {
            $stmt->bindParam($key, ...$value);
        }

        // Execute the PDO statement
        $stmt->execute();
    }

    public function rawSql(string $sql, array $bindings = [])
    {
        $stmt = $this->pdo->prepare($sql);
        foreach ($bindings as $key => $value) {
            $stmt->bindParam($key, ...$value);
        }
        $stmt->execute();
    }

    public function transaction(callable $callback, ...$args)
    {
        try {
            $this->pdo->beginTransaction();
            $result = \call_user_func($callback, ...$args);
            $this->pdo->commit();

            return $result;
        } catch (\Throwable $e) {
            $this->pdo->rollback();
            throw $e;
        }
    }

    /**
     * Returns the pdo isntance.
     *
     * @return \PDO
     */
    public function getPdo()
    {
        return $this->pdo;
    }

    private function prepareCreateQuery(array $values, &$bindings)
    {
        $query = [];
        foreach ($values as $key => $value) {
            $query[] = ":$key";
            $bindings[$key] = [$value, is_numeric($value) ? \PDO::PARAM_INT : \PDO::PARAM_STR];
        }

        return implode(', ', $query);
    }

    private function buildUpdateQueryString(array $values, array &$bindings)
    {
        $query = [];
        foreach ($values as $key => $value) {
            $upColumnKey = sprintf('up_%s', $key);
            $query[] = sprintf('%s = %s', (string) $key, ":$upColumnKey");
            $bindings[$upColumnKey] = [$value, is_numeric($value) ? \PDO::PARAM_INT : \PDO::PARAM_STR];
        }

        return implode(', ', $query);
    }

    private function buildConditionQuery(array $conditions, array &$bindings)
    {
        $string = [];
        foreach ($conditions as $key => $value) {
            if (is_numeric($key)) {
                if (\is_array($value)) {
                    $this->buildArrayQueryConditions($value, $string, $bindings);
                }
                continue;
            }
            if (true === $value) {
                $string[] = sprintf('NOT NULL :%s', (string) $key);
                $bindings[$key] = [(string) $key, \PDO::PARAM_STR];
                continue;
            }
            $string[] = sprintf('%s = %s', (string) $key, ":$key");
            $bindings[$key] = [$value, is_numeric($value) ? \PDO::PARAM_INT : \PDO::PARAM_STR];
        }

        return sprintf('WHERE %s', implode(' AND ', $string));
    }

    private function buildArrayQueryConditions(array $condition, array &$query, array &$bindings)
    {
        [$column, $operator, $value] = $condition;
        if (null === $operator && null === $value) {
            $query[] = sprintf('NOT NULL :%s', (string) $column);
            $bindings[$column] = [(string) $column, \PDO::PARAM_STR];

            return;
        }

        if (null === $value) {
            $value = $operator;
            $operator = '=';
        }

        $query[] = sprintf('%s %s %s', (string) $column, $operator, ":$column");
        $bindings[$column] = [$value, is_numeric($value) ? \PDO::PARAM_INT : \PDO::PARAM_STR];
    }

    private function prepareStatement(string $sql)
    {
        if (null === $this->table) {
            throw new \BadMethodCallException('Database table must be selected before executing queries');
        }
        $stmt = $this->pdo->prepare($sql);
        if (false === $stmt) {
            [$err, $_, $message] = $this->pdo->errorInfo();
            throw new \PDOException($message ?? sprintf('SQL ERROR: %s', $sql, $err ? (int) $err : 500));
        }

        return $stmt;
    }
}
